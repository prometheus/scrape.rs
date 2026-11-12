// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contiguous arena-backed string interner whose internal layout matches Arrow's `StringArray`.

use arrow_array::StringArray;
use arrow_buffer::{Buffer, OffsetBuffer, ScalarBuffer};

/// Sentinel `Bucket::id` marking an unoccupied open-addressed hash table slot.
const EMPTY_SLOT: u32 = u32::MAX;

/// Multiplicative constant from `rustc-hash` (`FxHasher`), derived from the golden ratio over
/// 64 bits.
const FX_SEED: u64 = 0x517c_c1b7_2722_0a95;

/// Open-addressed hash table slot mapping a string's 64-bit hash to its interned `u32` ID.
///
/// Storing `hash` inline beside `id` lets linear probing skip non-matching slots in contiguous
/// `Bucket` memory without touching the `offsets` or `bytes` buffers until a hash match occurs.
#[derive(Clone, Copy)]
struct Bucket {
    /// Cached `fx_hash` of the interned byte slice, or `0` when `id == EMPTY_SLOT`.
    hash: u64,
    /// Index into `StringInterner::offsets` (`0..len()`), or `EMPTY_SLOT` when vacant.
    id: u32,
}

impl Bucket {
    const EMPTY: Self = Self {
        hash: 0,
        id: EMPTY_SLOT,
    };
}

/// Fast non-cryptographic byte hash used for per-scrape label and metric-name interning.
#[inline]
fn fx_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_le_bytes(*chunk);
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
    for &b in remainder {
        hash = (hash.rotate_left(5) ^ u64::from(b)).wrapping_mul(FX_SEED);
    }
    // Wrapping multiplication only carries bits from low to high, so changes in the trailing
    // bytes of the last 8-byte chunk never reach the low bits masked for bucket indexing. Fold
    // the upper half down bijectively so short IDs differing at the end spread across slots.
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    hash ^ (hash >> 32)
}

/// Reusable open-addressed string interner backed by a single `Vec<u8>` buffer and `Vec<i32>`
/// offset table.
///
/// Storing unique strings directly in Arrow's `(offsets, values)` layout avoids per-string `String`
/// heap allocations during scraping and materializes dictionary value arrays in two contiguous
/// buffer copies at the end of a scrape.
pub(super) struct StringInterner {
    bytes: Vec<u8>,
    offsets: Vec<i32>,
    buckets: Vec<Bucket>,
}

impl StringInterner {
    pub(super) const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            offsets: Vec::new(),
            buckets: Vec::new(),
        }
    }

    pub(super) fn with_capacity(strings: usize, byte_cap: usize) -> Self {
        if strings == 0 && byte_cap == 0 {
            return Self::new();
        }
        let bucket_cap = (strings.saturating_mul(2)).next_power_of_two().max(16);
        let mut offsets = Vec::with_capacity(strings + 1);
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(byte_cap),
            offsets,
            buckets: vec![Bucket::EMPTY; bucket_cap],
        }
    }

    /// Resets the interner for the next scrape while preserving backing capacities.
    pub(super) fn clear(&mut self) {
        self.bytes.clear();
        if !self.offsets.is_empty() {
            self.offsets.clear();
            self.offsets.push(0);
        }
        self.buckets.fill(Bucket::EMPTY);
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.bytes.capacity()
            + self.offsets.capacity() * size_of::<i32>()
            + self.buckets.capacity() * size_of::<Bucket>()
    }

    #[inline]
    pub(super) fn get(&self, id: u32) -> &str {
        let idx = id as usize;
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        // Every inserted slice is already validated `&str` UTF-8.
        std::str::from_utf8(&self.bytes[start..end]).unwrap_or_default()
    }

    #[inline]
    pub(super) fn get_bytes(&self, id: u32) -> &[u8] {
        let idx = id as usize;
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        &self.bytes[start..end]
    }

    /// Looks up a previously interned byte slice without inserting it.
    #[inline]
    pub(super) fn lookup(&self, raw: &[u8]) -> Option<u32> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = fx_hash(raw);
        let mask = self.buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        loop {
            let bucket = self.buckets[slot];
            if bucket.id == EMPTY_SLOT {
                return None;
            }
            if bucket.hash == hash && self.get_bytes(bucket.id) == raw {
                return Some(bucket.id);
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Interns UTF-8 validated `raw` bytes, returning `Some(id)` or `None` if the cumulative byte
    /// arena exceeds `i32::MAX`.
    #[inline]
    pub(super) fn intern(&mut self, raw: &[u8]) -> Option<u32> {
        if self.buckets.is_empty() {
            self.offsets.push(0);
            self.buckets.resize(16, Bucket::EMPTY);
        }
        let hash = fx_hash(raw);
        let mask = self.buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        loop {
            let bucket = self.buckets[slot];
            if bucket.id == EMPTY_SLOT {
                break;
            }
            if bucket.hash == hash && self.get_bytes(bucket.id) == raw {
                return Some(bucket.id);
            }
            slot = (slot + 1) & mask;
        }

        let next_len = self.bytes.len().checked_add(raw.len())?;
        let next_offset = i32::try_from(next_len).ok()?;
        let id = u32::try_from(self.len()).ok()?;
        if id == EMPTY_SLOT {
            return None;
        }

        self.bytes.extend_from_slice(raw);
        self.offsets.push(next_offset);
        self.buckets[slot] = Bucket { hash, id };

        // Grow at ~70% load factor (`10 * len >= 7 * cap`) to keep linear probing chains short.
        if self.len() * 10 >= self.buckets.len() * 7 {
            self.rehash();
        }
        Some(id)
    }

    #[cold]
    fn rehash(&mut self) {
        let new_cap = (self.buckets.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next_buckets = vec![Bucket::EMPTY; new_cap];
        for &bucket in &self.buckets {
            if bucket.id == EMPTY_SLOT {
                continue;
            }
            let mut slot = (bucket.hash as usize) & mask;
            while next_buckets[slot].id != EMPTY_SLOT {
                slot = (slot + 1) & mask;
            }
            next_buckets[slot] = bucket;
        }
        self.buckets = next_buckets;
    }

    /// Materializes all interned strings in insertion order (`0..len()`) as an Arrow `StringArray`.
    pub(super) fn to_string_array(&self) -> StringArray {
        let offsets_slice = if self.offsets.is_empty() {
            &[0i32][..]
        } else {
            &self.offsets[..]
        };
        let offsets_buf = Buffer::from_slice_ref(offsets_slice);
        let offsets = OffsetBuffer::new(ScalarBuffer::<i32>::new(
            offsets_buf,
            0,
            offsets_slice.len(),
        ));
        let values = Buffer::from_slice_ref(&self.bytes);
        // SAFETY-FREE invariant: every interned entry came from a valid `&str`, and `self.offsets`
        // is monotonically non-decreasing starting at `0` and ending at `self.bytes.len()`.
        StringArray::new(offsets, values, None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn fx_hash_spreads_8_byte_ids_differing_only_in_trailing_bytes() {
        let mut interner = StringInterner::with_capacity(4096, 4096 * 8);
        let mask = interner.buckets.len() - 1;
        let mut initial_slots = HashSet::with_capacity(4096);

        for i in 0..4096_u32 {
            let s = format!("h{i:07}");
            assert_eq!(s.len(), 8);
            initial_slots.insert((fx_hash(s.as_bytes()) as usize) & mask);
            assert_eq!(interner.intern(s.as_bytes()), Some(i));
            assert_eq!(interner.intern(s.as_bytes()), Some(i));
        }
        assert!(
            initial_slots.len() > 3000,
            "expected >3000 distinct initial slots across 8192 buckets, got {}",
            initial_slots.len()
        );

        // Byte 7 (bits 56..63) must also mix down into small 16-slot masks.
        let byte7_slots: HashSet<usize> = (b'a'..=b'z')
            .map(|ch| {
                let s = [b'h', b'o', b's', b't', b'0', b'0', b'0', ch];
                (fx_hash(&s) as usize) & 15
            })
            .collect();
        assert!(
            byte7_slots.len() >= 10,
            "expected byte-7 differences to spread across 16-slot mask, got {}",
            byte7_slots.len()
        );
    }
}
