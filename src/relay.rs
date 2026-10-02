//! Cacheline-padded, lock-free SPSC ring for completion-event dispatch.
//!
//! The engine thread produces [`Cqe`](crate::engine::Cqe)-shaped results;
//! another thread consumes them (control plane, response assembly). One
//! producer, one consumer; `try_push`/`try_pop` only, so neither side ever
//! blocks. Zero `SeqCst`; the handoff edge is the standard acquire/release
//! message-passing pair:
//!
//! * producer: slot write → `Release` sequence → `Relaxed` head bump
//! * consumer: `Acquire` sequence check → slot take → `Release` recycle
//!
//! Extracted from vane-core's `spsc.rs` (its worker command path), renamed
//! for its substrate role: relaying completions off the ring thread. Loom
//! model-checking: `tests/loom_relay.rs` (real ring) + `relay_model` double
//! (exhaustive ordering-protocol exploration).

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Pads to a cache line so the two cursors never false-share.
#[repr(align(64))]
#[derive(Default)]
struct Padded(AtomicUsize);

/// A bounded SPSC ring. `CAP` must be a power of two.
pub struct SpscRing<T, const CAP: usize> {
    mask: usize,
    head: Padded, // producer cursor (slots written)
    tail: Padded, // consumer cursor (slots read)
    slots: Box<[Slot<T>]>,
}

struct Slot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<Option<T>>,
}

// SAFETY: single producer + single consumer, enforced by &mut / &self split;
// T crossing threads requires T: Send.
unsafe impl<T: Send, const CAP: usize> Send for SpscRing<T, CAP> {}
// SAFETY: shared access is atomics-only; payloads move via the sequence
// protocol (one consumer takes ownership).
unsafe impl<T: Send, const CAP: usize> Sync for SpscRing<T, CAP> {}

impl<T, const CAP: usize> SpscRing<T, CAP> {
    /// Creates the ring.
    #[must_use]
    pub fn new() -> Self {
        const {
            assert!(CAP.is_power_of_two(), "CAP must be a power of two");
        }
        let slots = (0..CAP)
            .map(|i| Slot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(None),
            })
            .collect::<Vec<_>>();
        Self {
            mask: CAP - 1,
            head: Padded::default(),
            tail: Padded::default(),
            slots: slots.into_boxed_slice(),
        }
    }

    /// Producer: attempts to enqueue, returns `Some(value)` when full.
    #[inline]
    pub fn try_push(&self, value: T) -> Option<T> {
        let pos = self.head.0.load(Ordering::Relaxed);
        let slot = self.slots.get(pos & self.mask)?; // unreachable: masked
        if slot.sequence.load(Ordering::Acquire) != pos {
            return Some(value); // full
        }
        // SAFETY: sequence == pos means the slot is empty and exclusively
        // claimable by the (single) producer.
        unsafe {
            *slot.value.get() = Some(value);
        }
        slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
        self.head.0.store(pos.wrapping_add(1), Ordering::Relaxed);
        None
    }

    /// Consumer: attempts to dequeue, `None` when empty.
    #[inline]
    pub fn try_pop(&self) -> Option<T> {
        let pos = self.tail.0.load(Ordering::Relaxed);
        let slot = self.slots.get(pos & self.mask)?; // unreachable: masked
        if slot.sequence.load(Ordering::Acquire) != pos + 1 {
            return None; // empty
        }
        // SAFETY: sequence == pos + 1 means a value was published (release)
        // and this (single) consumer owns the take.
        let value = unsafe { (*slot.value.get()).take() };
        slot.sequence
            .store(pos.wrapping_add(CAP), Ordering::Release);
        self.tail.0.store(pos.wrapping_add(1), Ordering::Relaxed);
        value
    }

    /// Approximate occupancy (Relaxed, hint only).
    #[must_use]
    pub fn len(&self) -> usize {
        self.head
            .0
            .load(Ordering::Relaxed)
            .wrapping_sub(self.tail.0.load(Ordering::Relaxed))
    }

    /// `true` when the ring appears empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, const CAP: usize> Default for SpscRing<T, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Pairs a ring with its two ends for handing to separate threads.
#[must_use]
pub fn channel<T, const CAP: usize>() -> (SpscSender<T, CAP>, SpscReceiver<T, CAP>) {
    let ring = std::sync::Arc::new(SpscRing::new());
    (
        SpscSender {
            ring: std::sync::Arc::clone(&ring),
        },
        SpscReceiver { ring },
    )
}

/// Producer handle.
pub struct SpscSender<T, const CAP: usize> {
    ring: std::sync::Arc<SpscRing<T, CAP>>,
}

impl<T, const CAP: usize> SpscSender<T, CAP> {
    /// Enqueues without blocking; `Err(value)` when full.
    ///
    /// # Errors
    /// Returns the value back when the ring is full (lock-free bound).
    #[inline]
    pub fn send(&self, value: T) -> Result<(), T> {
        match self.ring.try_push(value) {
            None => Ok(()),
            Some(back) => Err(back),
        }
    }
}

/// Consumer handle.
pub struct SpscReceiver<T, const CAP: usize> {
    ring: std::sync::Arc<SpscRing<T, CAP>>,
}

impl<T, const CAP: usize> SpscReceiver<T, CAP> {
    /// Dequeues without blocking.
    #[inline]
    #[must_use]
    pub fn recv(&self) -> Option<T> {
        self.ring.try_pop()
    }

    /// Occupancy hint of the underlying ring (diagnostic aid).
    #[must_use]
    pub fn ring_len_hint(&self) -> usize {
        self.ring.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_basic_handoff() {
        let (tx, rx) = channel::<u64, 4>();
        tx.send(1).expect("fits");
        tx.send(2).expect("fits");
        assert_eq!(rx.recv(), Some(1));
        assert_eq!(rx.recv(), Some(2));
        assert_eq!(rx.recv(), None);
    }

    #[test]
    fn full_returns_back() {
        let (tx, rx) = channel::<u8, 2>();
        tx.send(1).unwrap_or(());
        tx.send(2).unwrap_or(());
        assert_eq!(tx.send(3), Err(3));
        assert_eq!(rx.recv(), Some(1));
        tx.send(3).expect("space now");
        assert_eq!(rx.recv(), Some(2));
        assert_eq!(rx.recv(), Some(3));
    }

    #[test]
    fn wraparound() {
        // Miri slows interpretation ~10kx: scale the loop to its budget.
        const ROUNDS: usize = if cfg!(miri) { 200 } else { 10_000 };
        let (tx, rx) = channel::<usize, 4>();
        for i in 0..ROUNDS {
            tx.send(i).expect("loop drains");
            assert_eq!(rx.recv(), Some(i));
        }
    }

    #[test]
    fn cross_thread_sum() {
        const MSGS: u64 = if cfg!(miri) { 200 } else { 100_000 };
        let (tx, rx) = channel::<u64, 1024>();
        std::thread::scope(|s| {
            s.spawn(|| {
                for i in 0..MSGS {
                    while tx.send(i).is_err() {
                        std::hint::spin_loop();
                    }
                }
            });
            let got: u64 = (0..MSGS)
                .map(|_| loop {
                    if let Some(v) = rx.recv() {
                        break v;
                    }
                    std::hint::spin_loop();
                })
                .sum();
            assert_eq!(got, MSGS * (MSGS - 1) / 2);
        });
    }

    #[test]
    fn len_is_a_hint_never_over_capacity() {
        let (tx, rx) = channel::<u8, 4>();
        for i in 0..4u8 {
            tx.send(i).expect("fits");
        }
        assert!(tx.send(9).is_err(), "full");
        assert!(rx.ring_len_hint() <= 4);
        assert_eq!(rx.recv(), Some(0));
    }
}
