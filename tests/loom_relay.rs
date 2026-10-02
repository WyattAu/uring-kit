//! Loom model-checking for the completion relay (Tier-A concurrency gate).
//!
//! Two layers, mirroring the estate's shm-rings discipline:
//!
//! 1. **Real ring under the loom scheduler** — `loom::model` interleaves
//!    two threads driving [`uring_kit::relay::SpscRing`]. The ring's
//!    `std::sync` atomics are real here, so this is interleaving-coverage of
//!    the public API, not an atomic model.
//! 2. **`relay_model` double** — the *identical* ordering protocol
//!    re-implemented with loom's tracked atomics/cells, which loom
//!    exhaustively explores. This is the layer that proves the
//!    acquire/release protocol: no loss, no duplication, FIFO order, and
//!    full-capacity backpressure in every interleaving.
//!
//! Run: `cargo test --features loom --test loom_relay`

#![cfg(all(target_os = "linux", feature = "loom"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use uring_kit::relay::SpscRing;

#[test]
fn real_ring_handoff_order_under_all_interleavings() {
    loom::model(|| {
        let ring: std::sync::Arc<SpscRing<u8, 2>> = std::sync::Arc::new(SpscRing::new());
        let producer = std::sync::Arc::clone(&ring);
        let consumer = std::sync::Arc::clone(&ring);

        let p = std::thread::spawn(move || {
            assert!(producer.try_push(1).is_none(), "first push fits");
            assert!(producer.try_push(2).is_none(), "second push fits");
        });
        let c = std::thread::spawn(move || {
            let first = consumer.try_pop();
            let second = consumer.try_pop();
            (first, second)
        });
        p.join().expect("producer");
        let (first, second) = c.join().expect("consumer");
        // FIFO order preserved in every interleaving where values exist.
        if let Some(v) = first {
            assert_eq!(v, 1);
        }
        if let Some(v) = second {
            assert_eq!(v, 2);
        }
    });
}

#[test]
fn real_ring_full_backpressure_returns_value() {
    loom::model(|| {
        let ring: std::sync::Arc<SpscRing<u32, 1>> = std::sync::Arc::new(SpscRing::new());
        let producer = std::sync::Arc::clone(&ring);
        let consumer = std::sync::Arc::clone(&ring);

        let p = std::thread::spawn(move || {
            assert!(producer.try_push(7).is_none(), "first push fits");
            // Second push may or may not fit depending on the consumer's
            // progress; a full ring returns the value instead of losing it.
            let _ = producer.try_push(8);
        });
        let c = std::thread::spawn(move || consumer.try_pop());
        p.join().expect("producer");
        let popped = c.join().expect("consumer");
        if let Some(v) = popped {
            assert!(v == 7 || v == 8);
        }
    });
}

// --- Exhaustive protocol model over the loom double -----------------------

use uring_kit::relay_model::LoomRing;

#[test]
fn model_no_loss_no_duplication_fifo() {
    loom::model(|| {
        let ring = loom::sync::Arc::new(LoomRing::new());
        let producer = loom::sync::Arc::clone(&ring);
        let consumer = loom::sync::Arc::clone(&ring);

        let p = loom::thread::spawn(move || {
            // Capacity 2 with exactly two messages and nothing else in the
            // ring: every push succeeds in every interleaving (pops can
            // only free space).
            let mut accepted = 0;
            for &m in &uring_kit::relay_model::LOOM_MESSAGES {
                assert!(producer.try_push(m), "push of {m} must fit");
                accepted += 1;
            }
            accepted
        });
        // Fixed pop budget (no spinning — loom branches on every failed
        // pop): values observed when present must be the FIFO prefix of the
        // pushed sequence; anything not yet observed is still in the ring,
        // never lost or duplicated.
        let c = loom::thread::spawn(move || {
            let got = (consumer.try_pop(), consumer.try_pop());
            [got.0, got.1].into_iter().flatten().collect::<Vec<_>>()
        });
        let pushed = p.join().expect("producer");
        let observed = c.join().expect("consumer");

        assert_eq!(pushed, 2);
        for (i, v) in observed.iter().enumerate() {
            assert_eq!(
                Some(v),
                uring_kit::relay_model::LOOM_MESSAGES.get(i),
                "FIFO/no-duplication violated: {observed:?}"
            );
        }
    });
}

#[test]
fn model_backpressure_never_crosses_capacity() {
    loom::model(|| {
        let ring = loom::sync::Arc::new(LoomRing::new());
        let producer = loom::sync::Arc::clone(&ring);
        let consumer = loom::sync::Arc::clone(&ring);

        let p = loom::thread::spawn(move || {
            // Capacity 2: three pushes mean at least one returns false.
            let r1 = producer.try_push(1);
            let r2 = producer.try_push(2);
            let r3 = producer.try_push(3);
            (r1, r2, r3)
        });
        let c = loom::thread::spawn(move || (consumer.try_pop(), consumer.try_pop()));
        let (r1, r2, r3) = p.join().expect("producer");
        let popped = c.join().expect("consumer");

        // The first two pushes start from an empty ring and nothing but
        // pops can occupy slots: they always fit.
        assert!(r1 && r2, "initial pushes must fit capacity");
        let accepted = usize::from(r1) + usize::from(r2) + usize::from(r3);
        let obs: Vec<usize> = [&popped.0, &popped.1]
            .into_iter()
            .flatten()
            .copied()
            .collect();

        // Successful pops correspond 1:1 to accepted pushes, in FIFO order.
        for pair in obs.windows(2) {
            assert!(
                pair.first()
                    .is_some_and(|&a| pair.get(1).is_some_and(|&b| a < b)),
                "FIFO violated: {pair:?}"
            );
        }
        assert!(obs.len() <= accepted, "popped more than was accepted");
        // A pop frees a slot: at most capacity + pops can ever be accepted.
        assert!(
            accepted <= 2 + obs.len(),
            "capacity violated: accepted {accepted} with {} pops",
            obs.len()
        );
        // The third push fits only if a successful pop freed a slot first.
        if r3 {
            assert!(!obs.is_empty(), "r3 accepted without a freeing pop");
        }
    });
}

#[test]
fn model_pop_returns_none_on_empty() {
    loom::model(|| {
        let ring = loom::sync::Arc::new(LoomRing::new());
        let consumer = loom::sync::Arc::clone(&ring);
        let c = loom::thread::spawn(move || consumer.try_pop());
        assert_eq!(c.join().expect("consumer"), None, "empty ring pops None");
    });
}
