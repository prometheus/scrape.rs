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

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::scrape::ScrapeTarget;

const FNV_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

/// Computes the deterministic initial phase offset in `[0, interval)` for `target`.
///
/// Mirrors Go Prometheus `Target.offset` by hashing `jitter_seed`, the target URL, and sorted
/// target labels with 64-bit FNV-1a without heap allocations. Identical targets always map to the
/// same offset within `interval`, spreading targets evenly across the scrape window.
#[must_use]
pub fn target_offset(target: &ScrapeTarget, interval: Duration, jitter_seed: u64) -> Duration {
    let interval_ns = interval.as_nanos();
    if interval_ns == 0 {
        return Duration::ZERO;
    }
    let hash = hash_target_identity(target, jitter_seed);
    let rem_ns = u64::try_from(u128::from(hash) % interval_ns).unwrap_or(0);
    Duration::from_nanos(rem_ns)
}

fn hash_target_identity(target: &ScrapeTarget, jitter_seed: u64) -> u64 {
    let mut h = FNV_OFFSET_BASIS_64;
    h = fnv1a_bytes(h, &jitter_seed.to_le_bytes());
    h = fnv1a_bytes(h, target.url().as_str().as_bytes());
    h = fnv1a_byte(h, 0xff);
    for (k, v) in target.labels() {
        h = fnv1a_bytes(h, k.as_bytes());
        h = fnv1a_byte(h, 0x00);
        h = fnv1a_bytes(h, v.as_bytes());
        h = fnv1a_byte(h, 0xff);
    }
    h
}

#[inline]
const fn fnv1a_byte(mut hash: u64, byte: u8) -> u64 {
    hash ^= byte as u64;
    hash.wrapping_mul(FNV_PRIME_64)
}

#[inline]
fn fnv1a_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash = fnv1a_byte(hash, b);
    }
    hash
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TargetKey {
    url: String,
    labels: BTreeMap<String, String>,
}

impl TargetKey {
    pub(crate) fn from_target(target: &ScrapeTarget) -> Self {
        Self {
            url: target.url().as_str().to_owned(),
            labels: target.labels().clone(),
        }
    }
}

#[derive(Debug)]
struct TargetSlot {
    target: Arc<ScrapeTarget>,
    generation: u64,
    next_due: Instant,
    in_flight: bool,
    removed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeapEntry {
    due: Instant,
    slot_id: usize,
    generation: u64,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.due
            .cmp(&other.due)
            .then_with(|| self.slot_id.cmp(&other.slot_id))
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Target popped from [`TargetSchedule`] when its periodic scrape instant arrives.
#[derive(Clone, Debug)]
pub(crate) struct DueTarget {
    pub(crate) slot_id: usize,
    pub(crate) generation: u64,
    pub(crate) target: Arc<ScrapeTarget>,
}

/// Single-structure min-heap target timer queue (`O(N)` memory, `O(log N)` per scrape tick).
///
/// Replaces spawning one sleeping task per target with a compact slot table and priority queue,
/// preserving exact per-target periodic grids (`t_0 + offset + k * interval`) and skipping
/// overlapping scrapes of an already in-flight target.
#[derive(Debug)]
pub(crate) struct TargetSchedule {
    interval: Duration,
    jitter_seed: u64,
    next_generation: u64,
    slots: Vec<Option<TargetSlot>>,
    free_slots: Vec<usize>,
    index_by_key: HashMap<TargetKey, usize>,
    heap: BinaryHeap<Reverse<HeapEntry>>,
    overruns: u64,
}

impl TargetSchedule {
    pub(crate) fn new(interval: Duration, jitter_seed: u64) -> Self {
        Self {
            interval,
            jitter_seed,
            next_generation: 1,
            slots: Vec::new(),
            free_slots: Vec::new(),
            index_by_key: HashMap::new(),
            heap: BinaryHeap::new(),
            overruns: 0,
        }
    }

    /// Reconciles the active target list against `targets` at `base_instant`, returning any idle
    /// targets that were immediately removed from the schedule.
    ///
    /// Unchanged targets preserve their existing `next_due` phase and `in_flight` state; newly
    /// discovered targets are scheduled at `base_instant + target_offset(target)`. Duplicate
    /// targets within `targets` are deduplicated automatically. Targets removed while an active
    /// scrape is still `in_flight` are returned later from [`Self::complete`].
    pub(crate) fn sync_targets(
        &mut self,
        targets: Vec<ScrapeTarget>,
        base_instant: Instant,
    ) -> Vec<Arc<ScrapeTarget>> {
        let mut seen = HashSet::with_capacity(targets.len());

        for target in targets {
            let key = TargetKey::from_target(&target);
            if !seen.insert(key.clone()) {
                continue;
            }
            if self.index_by_key.contains_key(&key) {
                continue;
            }

            let generation = self.next_generation;
            self.next_generation = self.next_generation.wrapping_add(1);
            let offset = target_offset(&target, self.interval, self.jitter_seed);
            let due = base_instant + offset;

            let slot = TargetSlot {
                target: Arc::new(target),
                generation,
                next_due: due,
                in_flight: false,
                removed: false,
            };

            let slot_id = if let Some(reused) = self.free_slots.pop() {
                self.slots[reused] = Some(slot);
                reused
            } else {
                let id = self.slots.len();
                self.slots.push(Some(slot));
                id
            };

            self.index_by_key.insert(key, slot_id);
            self.heap.push(Reverse(HeapEntry {
                due,
                slot_id,
                generation,
            }));
        }

        let mut to_remove = Vec::new();
        for (key, &slot_id) in &self.index_by_key {
            if !seen.contains(key) {
                to_remove.push((key.clone(), slot_id));
            }
        }

        let mut removed_idle = Vec::new();
        for (key, slot_id) in to_remove {
            self.index_by_key.remove(&key);
            if let Some(slot) = self.slots.get_mut(slot_id).and_then(Option::as_mut) {
                if slot.in_flight {
                    slot.removed = true;
                } else {
                    if let Some(taken) = self.slots[slot_id].take() {
                        removed_idle.push(taken.target);
                    }
                    self.free_slots.push(slot_id);
                }
            }
        }
        removed_idle
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index_by_key.is_empty()
    }

    /// Returns the earliest `Instant` at which a valid non-removed target is due.
    pub(crate) fn peek_next_due(&mut self) -> Option<Instant> {
        while let Some(&Reverse(entry)) = self.heap.peek() {
            let valid = self
                .slots
                .get(entry.slot_id)
                .and_then(Option::as_ref)
                .is_some_and(|s| !s.removed && s.generation == entry.generation);
            if valid {
                return Some(entry.due);
            }
            self.heap.pop();
        }
        None
    }

    /// Pops one target whose scheduled `due <= now`, advancing its periodic timer to the next grid
    /// tick (`due + k * interval`) immediately so scrape latency never shifts future intervals.
    pub(crate) fn pop_due(&mut self, now: Instant) -> Option<DueTarget> {
        let interval_ns = self.interval.as_nanos().max(1);

        while let Some(&Reverse(entry)) = self.heap.peek() {
            if entry.due > now {
                return None;
            }
            self.heap.pop();

            let Some(slot) = self.slots.get_mut(entry.slot_id).and_then(Option::as_mut) else {
                continue;
            };
            if slot.removed || slot.generation != entry.generation {
                continue;
            }

            let elapsed = now.saturating_duration_since(entry.due);
            let missed_ticks = elapsed.as_nanos() / interval_ns + 1;
            let skipped = u64::try_from(missed_ticks.saturating_sub(1)).unwrap_or(u64::MAX);
            let advance = self
                .interval
                .saturating_mul(u32::try_from(missed_ticks).unwrap_or(u32::MAX));
            let mut next_due = entry.due + advance;
            if next_due <= now {
                next_due = now + self.interval;
            }
            slot.next_due = next_due;
            self.heap.push(Reverse(HeapEntry {
                due: next_due,
                slot_id: entry.slot_id,
                generation: slot.generation,
            }));

            if slot.in_flight {
                self.overruns = self.overruns.saturating_add(skipped.saturating_add(1));
                continue;
            }

            self.overruns = self.overruns.saturating_add(skipped);
            slot.in_flight = true;
            return Some(DueTarget {
                slot_id: entry.slot_id,
                generation: slot.generation,
                target: Arc::clone(&slot.target),
            });
        }
        None
    }

    /// Marks an in-flight scrape finished so the target may run on future ticks, returning the
    /// target if it was removed by [`Self::sync_targets`] while in flight.
    pub(crate) fn complete(
        &mut self,
        slot_id: usize,
        generation: u64,
    ) -> Option<Arc<ScrapeTarget>> {
        let reclaim = if let Some(slot) = self.slots.get_mut(slot_id).and_then(Option::as_mut)
            && slot.generation == generation
        {
            slot.in_flight = false;
            slot.removed
        } else {
            false
        };
        if reclaim {
            let removed = self.slots[slot_id].take().map(|s| s.target);
            self.free_slots.push(slot_id);
            removed
        } else {
            None
        }
    }

    /// Drains and returns newly accumulated interval overrun counts since the last call.
    pub(crate) fn take_overruns(&mut self) -> u64 {
        std::mem::take(&mut self.overruns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_offset_is_deterministic_and_bounded_by_interval() {
        let interval = Duration::from_secs(15);
        let t1 = ScrapeTarget::parse("http://10.0.0.1:9100/metrics")
            .expect("url")
            .with_label("pod", "a");
        let t2 = ScrapeTarget::parse("http://10.0.0.2:9100/metrics")
            .expect("url")
            .with_label("pod", "b");

        let off1_a = target_offset(&t1, interval, 42);
        let off1_b = target_offset(&t1, interval, 42);
        let off2 = target_offset(&t2, interval, 42);

        assert_eq!(off1_a, off1_b);
        assert!(off1_a < interval);
        assert!(off2 < interval);
        assert_ne!(off1_a, off2);
        assert_eq!(target_offset(&t1, Duration::ZERO, 42), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn schedule_preserves_phase_on_sync_and_counts_in_flight_overruns() {
        let interval = Duration::from_secs(10);
        let base = Instant::now();
        let t1 = ScrapeTarget::parse("http://127.0.0.1:8081/metrics").expect("t1");
        let t2 = ScrapeTarget::parse("http://127.0.0.1:8082/metrics").expect("t2");

        let mut sched = TargetSchedule::new(interval, 7);
        sched.sync_targets(vec![t1.clone()], base);

        let first_due = sched.peek_next_due().expect("has due");
        // Re-syncing t1 plus adding t2 right after first_due must keep t1's original first_due intact.
        let later = first_due + Duration::from_nanos(1);
        sched.sync_targets(vec![t1.clone(), t2.clone()], later);

        let due_at_first = first_due;
        let popped = sched.pop_due(due_at_first).expect("t1 due");
        assert_eq!(popped.target.url(), t1.url());
        assert_eq!(sched.take_overruns(), 0);

        // Leave t1 `in_flight` across its next due tick (`first_due + 10s`) -> skips and records 1 overrun.
        let second_tick = first_due + interval;
        while let Some(other) = sched.pop_due(second_tick) {
            // Only t2 can pop while t1 is still in_flight.
            assert_eq!(other.target.url(), t2.url());
            sched.complete(other.slot_id, other.generation);
        }
        assert_eq!(sched.take_overruns(), 1);

        // Completing t1 allows it to fire cleanly at `first_due + 20s`.
        sched.complete(popped.slot_id, popped.generation);
        let third_tick = first_due + interval * 2;
        let mut fired_urls = Vec::new();
        while let Some(d) = sched.pop_due(third_tick) {
            fired_urls.push(d.target.url().as_str().to_owned());
            sched.complete(d.slot_id, d.generation);
        }
        assert!(fired_urls.iter().any(|u| u == t1.url().as_str()));
    }
}
