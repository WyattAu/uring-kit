//! Criterion benches for the `io_uring` substrate: op round-trip latency,
//! buffer-pool hot path, splice pump throughput, relay handoff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use uring_kit::engine::Engine as _;
use uring_kit::{BufferPool, Op, Token, UringEngine, DEFAULT_BUF_SIZE};

fn sockpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: plain socketpair with a valid out-array.
    let rc = unsafe { libc_socketpair(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    let [fa, fb] = fds;
    (fa, fb)
}

// Tiny indirection so the bench has a single unsafe site.
///
/// # Safety
/// `fds` must point at a writable two-element fd array.
unsafe fn libc_socketpair(fds: *mut RawFd) -> i32 {
    // SAFETY: caller guarantees a writable out-array.
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds) }
}

fn bench_ring_roundtrip(c: &mut Criterion) {
    let pool = BufferPool::new(16, DEFAULT_BUF_SIZE).expect("pool");
    let mut engine = UringEngine::new(64, Some(&pool), false).expect("ring");
    let (a, b) = sockpair();
    let mut group = c.benchmark_group("ring_op_roundtrip");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("write_read_fixed_32b", |bench| {
        bench.iter_batched(
            || {
                (
                    Token::new(Op::Write, 0, 1, 0),
                    Token::new(Op::Read, 0, 2, 0),
                )
            },
            |(wt, rt)| {
                // One full submission→completion cycle per iteration.
                engine.write(wt, a, 0, 32, 0).expect("write");
                loop {
                    let mut out = Vec::new();
                    engine
                        .poll(Some(Duration::from_millis(100)), &mut out)
                        .expect("poll");
                    if out.iter().any(|cq| cq.token == wt) {
                        break;
                    }
                }
                engine.read(rt, b, 1).expect("read");
                loop {
                    let mut out = Vec::new();
                    engine
                        .poll(Some(Duration::from_millis(100)), &mut out)
                        .expect("poll");
                    if out.iter().any(|cq| cq.token == rt) {
                        break;
                    }
                }
            },
            criterion::BatchSize::PerIteration,
        );
    });
    group.finish();
    // SAFETY: test-owned fds.
    unsafe { libc::close(a) };
    // SAFETY: test-owned fds.
    unsafe { libc::close(b) };
}

fn bench_buffer_pool(c: &mut Criterion) {
    let mut pool = BufferPool::new(1024, DEFAULT_BUF_SIZE).expect("pool");
    c.bench_function("buffer_pool_take_release", |bench| {
        bench.iter(|| {
            let mut live = std::collections::VecDeque::new();
            for _ in 0..256 {
                if let Some(slot) = pool.take() {
                    if let Some(first) = pool.slot_mut(slot).first_mut() {
                        *first = 1;
                    }
                    live.push_back(slot);
                }
            }
            while let Some(slot) = live.pop_front() {
                pool.release(slot);
            }
        });
    });
}

fn bench_splice_pump(c: &mut Criterion) {
    let mut fds = [0 as RawFd; 2];
    assert_eq!(
        // SAFETY: plain pipe2 with a valid out-array.
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    let [pr, pw] = fds;
    let payload = vec![0u8; 64 * 1024];
    let devnull = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("devnull");
    let mut group = c.benchmark_group("splice_pump");
    group.throughput(criterion::Throughput::Bytes(payload.len() as u64));
    group.bench_function("pipe_to_devnull_64k", |bench| {
        bench.iter(|| {
            assert_eq!(
                // SAFETY: write to a live pipe end.
                unsafe { libc::write(pw, payload.as_ptr().cast(), payload.len()) },
                payload.len() as isize
            );
            match uring_kit::splice::pump(pr, devnull.as_raw_fd(), u64::from(u32::MAX)) {
                uring_kit::splice::PumpResult::Moved(n) => assert_eq!(n, payload.len() as u64),
                uring_kit::splice::PumpResult::Eof | uring_kit::splice::PumpResult::WouldBlock => {
                    unreachable!("devnull never backpressures or EOFs")
                }
                uring_kit::splice::PumpResult::Err(e) => unreachable!("pump error: {e}"),
            }
        });
    });
    group.finish();
    // SAFETY: test-owned pipe ends.
    unsafe { libc::close(pr) };
    // SAFETY: test-owned pipe ends.
    unsafe { libc::close(pw) };
}

fn bench_relay(c: &mut Criterion) {
    let (tx, rx) = uring_kit::relay::channel::<u32, 256>();
    c.bench_function("relay_spsc_handoff", |bench| {
        bench.iter(|| {
            for i in 0..256u32 {
                while tx.send(i).is_err() {
                    std::hint::spin_loop();
                }
            }
            for i in 0..256u32 {
                loop {
                    match rx.recv() {
                        Some(v) => {
                            assert_eq!(v, i);
                            break;
                        }
                        None => std::hint::spin_loop(),
                    }
                }
            }
        });
    });
}

criterion_group!(
    benches,
    bench_ring_roundtrip,
    bench_buffer_pool,
    bench_splice_pump,
    bench_relay
);
criterion_main!(benches);
