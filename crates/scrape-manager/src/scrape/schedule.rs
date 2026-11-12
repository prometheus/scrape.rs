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
use std::collections::{BinaryHeap, HashMap};
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

#[derive(Debug)]
struct TargetSlot {
    target: Arc<ScrapeTarget>,
    generation: u64,
    next_due: Instant,
    seen_epoch: u64,
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
    sync_epoch: u64,
    slots: Vec<Option<TargetSlot>>,
    free_slots: Vec<usize>,
    index_by_target: HashMap<Arc<ScrapeTarget>, usize>,
    removed_in_flight: HashMap<Arc<ScrapeTarget>, usize>,
    heap: BinaryHeap<Reverse<HeapEntry>>,
    overruns: u64,
}

impl TargetSchedule {
    pub(crate) fn new(interval: Duration, jitter_seed: u64) -> Self {
        Self {
            interval,
            jitter_seed,
            next_generation: 1,
            sync_epoch: 0,
            slots: Vec::new(),
            free_slots: Vec::new(),
            index_by_target: HashMap::new(),
            removed_in_flight: HashMap::new(),
            heap: BinaryHeap::new(),
            overruns: 0,
        }
    }

    /// Reconciles the active target list against `targets` at `base_instant`.
    ///
    /// Unchanged targets preserve their existing `next_due` phase and `in_flight` state without
    /// cloning URL or label allocations; newly discovered targets are scheduled at
    /// `base_instant + target_offset(target)`. Duplicate targets within `targets` are deduplicated
    /// automatically.
    pub(crate) fn sync_targets(&mut self, targets: Vec<ScrapeTarget>, base_instant: Instant) {
        self.sync_epoch = self.sync_epoch.wrapping_add(1);
        let epoch = self.sync_epoch;

        for target in targets {
            if let Some(&slot_id) = self.index_by_target.get(&target) {
                if let Some(slot) = self.slots.get_mut(slot_id).and_then(Option::as_mut) {
                    slot.seen_epoch = epoch;
                }
                continue;
            }

            // If `target` was removed while an earlier scrape was still in flight and re-added
            // before that scrape completed, revive the existing in-flight slot so two scrapes of
            // the same target never overlap.
            if let Some(slot_id) = self.removed_in_flight.remove(&target)
                && let Some(slot) = self.slots.get_mut(slot_id).and_then(Option::as_mut)
            {
                slot.removed = false;
                slot.seen_epoch = epoch;
                let due = slot.next_due;
                let generation = slot.generation;
                let target_arc = Arc::clone(&slot.target);
                self.index_by_target.insert(target_arc, slot_id);
                self.heap.push(Reverse(HeapEntry {
                    due,
                    slot_id,
                    generation,
                }));
                continue;
            }

            let generation = self.next_generation;
            self.next_generation = self.next_generation.wrapping_add(1);
            let offset = target_offset(&target, self.interval, self.jitter_seed);
            let due = base_instant.checked_add(offset).unwrap_or(base_instant);
            let target_arc = Arc::new(target);

            let slot = TargetSlot {
                target: Arc::clone(&target_arc),
                generation,
                next_due: due,
                seen_epoch: epoch,
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

            self.index_by_target.insert(target_arc, slot_id);
            self.heap.push(Reverse(HeapEntry {
                due,
                slot_id,
                generation,
            }));
        }

        let slots = &mut self.slots;
        let free_slots = &mut self.free_slots;
        let removed_in_flight = &mut self.removed_in_flight;
        self.index_by_target.retain(|target_key, &mut slot_id| {
            let Some(slot) = slots.get_mut(slot_id).and_then(Option::as_mut) else {
                return false;
            };
            if slot.seen_epoch == epoch {
                return true;
            }
            if slot.in_flight {
                slot.removed = true;
                removed_in_flight.insert(Arc::clone(target_key), slot_id);
            } else {
                slots[slot_id] = None;
                free_slots.push(slot_id);
            }
            false
        });

        let active = self.index_by_target.len();
        if self.heap.len() > active.saturating_mul(2).max(64) {
            self.compact_heap(active);
        }
    }

    fn compact_heap(&mut self, active: usize) {
        let mut rebuilt = BinaryHeap::with_capacity(active);
        for (slot_id, slot_opt) in self.slots.iter().enumerate() {
            if let Some(slot) = slot_opt
                && !slot.removed
            {
                rebuilt.push(Reverse(HeapEntry {
                    due: slot.next_due,
                    slot_id,
                    generation: slot.generation,
                }));
            }
        }
        self.heap = rebuilt;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index_by_target.is_empty()
    }

    /// Returns the earliest `Instant` at which a valid non-removed target is due.
    pub(crate) fn peek_next_due(&mut self) -> Option<Instant> {
        while let Some(&Reverse(entry)) = self.heap.peek() {
            let valid = self
                .slots
                .get(entry.slot_id)
                .and_then(Option::as_ref)
                .is_some_and(|s| {
                    !s.removed && s.generation == entry.generation && s.next_due == entry.due
                });
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
        while let Some(&Reverse(entry)) = self.heap.peek() {
            if entry.due > now {
                return None;
            }
            self.heap.pop();

            let Some(slot) = self.slots.get_mut(entry.slot_id).and_then(Option::as_mut) else {
                continue;
            };
            if slot.removed || slot.generation != entry.generation || slot.next_due != entry.due {
                continue;
            }

            let (next_due, missed_ticks) = advance_grid_deadline(entry.due, now, self.interval);
            let skipped = missed_ticks.saturating_sub(1);
            slot.next_due = next_due;
            self.heap.push(Reverse(HeapEntry {
                due: next_due,
                slot_id: entry.slot_id,
                generation: slot.generation,
            }));

            if slot.in_flight {
                self.overruns = self.overruns.saturating_add(missed_ticks);
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

    /// Marks an in-flight scrape finished at `now`, advancing past any periodic ticks that elapsed
    /// while the scrape was still running (for example when `in_flight.len() == max_in_flight`
    /// suppressed `pop_due` during the overrun).
    pub(crate) fn complete(&mut self, slot_id: usize, generation: u64, now: Instant) {
        let mut new_heap_entry = None;
        let mut added_overruns = 0_u64;
        let reclaim = if let Some(slot) = self.slots.get_mut(slot_id).and_then(Option::as_mut)
            && slot.generation == generation
        {
            slot.in_flight = false;
            if slot.removed {
                Some(Arc::clone(&slot.target))
            } else {
                if slot.next_due <= now {
                    let (next_due, missed_ticks) =
                        advance_grid_deadline(slot.next_due, now, self.interval);
                    slot.next_due = next_due;
                    added_overruns = missed_ticks;
                    new_heap_entry = Some(HeapEntry {
                        due: next_due,
                        slot_id,
                        generation: slot.generation,
                    });
                }
                None
            }
        } else {
            None
        };
        if added_overruns > 0 {
            self.overruns = self.overruns.saturating_add(added_overruns);
        }
        if let Some(entry) = new_heap_entry {
            self.heap.push(Reverse(entry));
        }
        if let Some(target) = reclaim {
            self.removed_in_flight.remove(&target);
            self.slots[slot_id] = None;
            self.free_slots.push(slot_id);
        }
    }

    /// Drains and returns newly accumulated interval overrun counts since the last call.
    pub(crate) fn take_overruns(&mut self) -> u64 {
        std::mem::take(&mut self.overruns)
    }
}

/// Advances `due` (`<= now`) forward by `k * interval` onto the earliest grid instant strictly
/// after `now`, returning `(next_due, k)` without panicking on `Duration` or `Instant` overflow.
pub(crate) fn advance_grid_deadline(
    due: Instant,
    now: Instant,
    interval: Duration,
) -> (Instant, u64) {
    let interval_ns = interval.as_nanos().max(1);
    let elapsed = now.saturating_duration_since(due);
    let missed_ticks = elapsed.as_nanos() / interval_ns + 1;
    let next_due = u32::try_from(missed_ticks)
        .ok()
        .and_then(|ticks| interval.checked_mul(ticks))
        .and_then(|advance| due.checked_add(advance))
        .filter(|&candidate| candidate > now)
        .or_else(|| now.checked_add(interval))
        .unwrap_or(now);
    let missed_u64 = u64::try_from(missed_ticks).unwrap_or(u64::MAX);
    (next_due, missed_u64)
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
            sched.complete(other.slot_id, other.generation, second_tick);
        }
        assert_eq!(sched.take_overruns(), 1);

        // Completing t1 allows it to fire cleanly at `first_due + 20s`.
        sched.complete(
            popped.slot_id,
            popped.generation,
            second_tick + Duration::from_secs(1),
        );
        let third_tick = first_due + interval * 2;
        let mut fired_urls = Vec::new();
        while let Some(d) = sched.pop_due(third_tick) {
            fired_urls.push(d.target.url().as_str().to_owned());
            sched.complete(d.slot_id, d.generation, third_tick);
        }
        assert!(fired_urls.iter().any(|u| u == t1.url().as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn readding_in_flight_target_does_not_overlap() {
        let interval = Duration::from_secs(10);
        let base = Instant::now();
        let t1 = ScrapeTarget::parse("http://127.0.0.1:8090/metrics").expect("t1");

        let mut sched = TargetSchedule::new(interval, 11);
        sched.sync_targets(vec![t1.clone()], base);

        let first_due = sched.peek_next_due().expect("due");
        let active = sched.pop_due(first_due).expect("pop first");

        // Flap SD: remove `t1` while in flight, peek (which drops its heap entry), then re-add `t1`.
        sched.sync_targets(Vec::new(), first_due + Duration::from_secs(1));
        assert!(sched.is_empty());
        assert!(sched.peek_next_due().is_none());

        sched.sync_targets(vec![t1.clone()], first_due + Duration::from_secs(2));
        assert!(!sched.is_empty());

        // At the next grid tick while the first scrape is still running, `pop_due` must skip `t1`
        // and count 1 overrun rather than starting an overlapping second scrape.
        assert!(sched.pop_due(first_due + interval).is_none());
        assert_eq!(sched.take_overruns(), 1);

        // Once the first scrape finishes, `t1` runs on the following tick.
        sched.complete(
            active.slot_id,
            active.generation,
            first_due + interval + Duration::from_secs(1),
        );
        let next = sched
            .pop_due(first_due + interval * 2)
            .expect("fires after completion");
        assert_eq!(next.target.url(), t1.url());
    }

    #[tokio::test(start_paused = true)]
    async fn complete_after_saturated_overrun_skips_missed_tick_and_counts_overrun() {
        let interval = Duration::from_secs(10);
        let base = Instant::now();
        let t1 = ScrapeTarget::parse("http://127.0.0.1:8091/metrics").expect("t1");

        let mut sched = TargetSchedule::new(interval, 19);
        sched.sync_targets(vec![t1.clone()], base);

        let first_due = sched.peek_next_due().expect("due");
        let active = sched.pop_due(first_due).expect("pop first");

        // Simulate `in_flight.len() == max_in_flight`: `pop_due` is never called at `first_due + 10s`,
        // and the scrape finishes 4s into the missed interval (`first_due + 14s`).
        let finish_at = first_due + Duration::from_secs(14);
        sched.complete(active.slot_id, active.generation, finish_at);
        assert_eq!(sched.take_overruns(), 1);

        // Must NOT immediately re-scrape at `first_due + 14s`; must wait until `first_due + 20s`.
        assert!(sched.pop_due(finish_at).is_none());
        let resumed = sched
            .pop_due(first_due + interval * 2)
            .expect("fires on next grid tick");
        assert_eq!(resumed.target.url(), t1.url());
    }

    #[tokio::test(start_paused = true)]
    async fn rapid_target_churn_compacts_stale_heap_entries() {
        let interval = Duration::from_secs(60);
        let base = Instant::now();
        let mut sched = TargetSchedule::new(interval, 3);

        for batch in 0..200 {
            let t = ScrapeTarget::parse(&format!("http://127.0.0.1:9100/m/{batch}")).expect("url");
            sched.sync_targets(vec![t], base);
        }
        assert!(
            sched.heap.len() <= 64,
            "expected compacted heap <= 64 entries after churn, got {}",
            sched.heap.len()
        );
    }
}
