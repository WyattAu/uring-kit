//! Loom model double of the completion relay (compiled only with the
//! `loom` feature).
//!
//! The real [`crate::relay::SpscRing`] is model-checked two ways:
//! `tests/loom_relay.rs` runs `loom::model` over the real ring (scheduler
//! interleavings), and this double re-implements the *identical* ordering
//! protocol with loom's own tracked types so the acquire/release discipline
//! itself is exhaustively explored:
//!
//! * producer: slot write (cell `set`, loom-tracked) → `Release` sequence →
//!   `Relaxed` head bump
//! * consumer: `Acquire` sequence check → cell `get` → `Release` recycle
//!
//! Capacity is fixed at 2 and message counts are tiny so the state space
//! stays tractable.

use loom::cell::UnsafeCell;
use loom::sync::atomic::{
    AtomicUsize,
    Ordering::{Acquire, Relaxed, Release},
};

/// Modeled capacity.
const LOOM_CAPACITY: usize = 2;

/// In-memory loom double of [`crate::relay::SpscRing`] (usize payloads).
pub struct LoomRing {
    head: AtomicUsize,
    tail: AtomicUsize,
    sequence: [AtomicUsize; LOOM_CAPACITY],
    slots: [UnsafeCell<Option<usize>>; LOOM_CAPACITY],
}

// SAFETY: mirrors the real ring's argument. All cross-thread state is
// loom atomics (head, tail, sequence) or loom-tracked cells whose access is
// ordered by the same acquire/release sequence protocol the real ring uses.
unsafe impl Send for LoomRing {}
// SAFETY: shared access is loom-atomics-only; the payload moves through the
// sequence protocol to the single consumer.
unsafe impl Sync for LoomRing {}

impl LoomRing {
    /// Creates the double with the real ring's initial sequence state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            sequence: [AtomicUsize::new(0), AtomicUsize::new(1)],
            slots: [UnsafeCell::new(None), UnsafeCell::new(None)],
        }
    }

    /// Slot pair for a masked index (constant-dispatch, no slicing).
    fn slot_pair(&self, idx: usize) -> (&AtomicUsize, &UnsafeCell<Option<usize>>) {
        if idx & 1 == 0 {
            (&self.sequence[0], &self.slots[0])
        } else {
            (&self.sequence[1], &self.slots[1])
        }
    }

    /// Producer attempt — identical protocol to `SpscRing::try_push`.
    pub fn try_push(&self, value: usize) -> bool {
        let pos = self.head.load(Relaxed);
        let (sequence, slot) = self.slot_pair(pos);
        if sequence.load(Acquire) != pos {
            return false; // full
        }
        // sequence == pos grants the single producer exclusive access to
        // this slot; loom's cell is a scheduler-tracked UnsafeCell whose
        // raw pointer is only ever dereferenced under its with_mut.
        slot.with_mut(|v| unsafe {
            // SAFETY: exclusive slot access per the sequence protocol.
            *v = Some(value);
        });
        sequence.store(pos.wrapping_add(1), Release);
        self.head.store(pos.wrapping_add(1), Relaxed);
        true
    }

    /// Consumer attempt — identical protocol to `SpscRing::try_pop`.
    pub fn try_pop(&self) -> Option<usize> {
        let pos = self.tail.load(Relaxed);
        let (sequence, slot) = self.slot_pair(pos);
        if sequence.load(Acquire) != pos + 1 {
            return None; // empty
        }
        // sequence == pos + 1 means the producer's Release published a
        // value and this (single) consumer owns the take.
        let value = slot.with_mut(|v| unsafe {
            // SAFETY: exclusive slot access per the sequence protocol.
            (*v).take()
        });
        sequence.store(pos.wrapping_add(LOOM_CAPACITY), Release);
        self.tail.store(pos.wrapping_add(1), Relaxed);
        value
    }
}

impl Default for LoomRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Message codes pushed by loom scenarios (kept tiny).
pub const LOOM_MESSAGES: [usize; 2] = [1, 2];
