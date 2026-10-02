//! Integration tests against a real kernel (Linux-required by the crate's
//! platform declaration): ring lifecycle, feature probing, full op
//! round-trips, and cross-thread completion dispatch through the relay.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use uring_kit::engine::{Cqe, Engine, Poll};
use uring_kit::{BufferPool, Op, Probe, Token, UringEngine, DEFAULT_BUF_SIZE};

fn tok(op: Op, gen: u16) -> Token {
    Token::new(op, 0, gen, 0)
}

fn sockpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: plain socketpair with a valid out-array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    for fd in fds {
        // SAFETY: fcntl on a live fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: same live fd; only adds O_NONBLOCK.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    (fds[0], fds[1])
}

fn drain_until(engine: &mut UringEngine, mut pred: impl FnMut(&Cqe) -> bool) -> Vec<Cqe> {
    let mut all = Vec::new();
    for _ in 0..80 {
        let mut out = Vec::new();
        engine
            .poll(Some(Duration::from_millis(50)), &mut out)
            .expect("poll");
        let hit = out.iter().any(&mut pred);
        all.extend(out);
        if hit {
            return all;
        }
    }
    all
}

#[test]
fn probe_detects_the_test_kernel() {
    let probe = Probe::detect().expect("io_uring on the CI/dev kernel");
    assert!(probe.at_least(5, 1), "io_uring baseline is 5.1");
    assert!(probe.supports_registered_buffers());
    assert!(
        probe.supports_opcode(io_uring_accept_code()),
        "ACCEPT probed"
    );
    // The engine builds on top of what the probe reports.
    let pool = BufferPool::new(16, DEFAULT_BUF_SIZE).expect("pool");
    let engine = UringEngine::new(32, Some(&pool), false).expect("ring");
    assert_eq!(engine.kind(), "io_uring");
}

fn io_uring_accept_code() -> u8 {
    io_uring::opcode::Accept::CODE
}

#[test]
fn ring_lifecycle_pool_registration_and_teardown() {
    // Create/register/drop repeatedly: fd and registration leaks would
    // surface as EMFILE across iterations.
    for _ in 0..8 {
        let pool = BufferPool::new(8, DEFAULT_BUF_SIZE).expect("pool");
        let mut engine = UringEngine::new(16, Some(&pool), false).expect("ring");
        let (a, b) = sockpair();
        let t = tok(Op::Write, 1);
        engine.write(t, a, 0, 4, 0).expect("write queued");
        let cqes = drain_until(&mut engine, |c| c.token == t);
        assert!(cqes
            .iter()
            .any(|c| c.token == t && matches!(c.result, Ok(4))));
        // SAFETY: test-owned fds.
        unsafe { libc::close(a) };
        // SAFETY: test-owned fds.
        unsafe { libc::close(b) };
        drop(engine); // unregisters buffers, closes the ring fds
    }
}

#[test]
fn echo_round_trip_over_tcp_with_registered_buffers() {
    let listener = uring_kit::net::tcp_listener("127.0.0.1:0".parse().expect("addr"), false, 16)
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let lfd = listener.as_raw_fd();

    let mut pool = BufferPool::new(16, DEFAULT_BUF_SIZE).expect("pool");
    let mut engine = UringEngine::new(64, Some(&pool), false).expect("ring");
    engine
        .add_listener(lfd, Token::accept(0))
        .expect("register");

    // Client dials through the ring itself.
    let ct = tok(Op::Connect, 7);
    let (cfd, _) = engine.connect(ct, addr).expect("connect queued");
    let cqes = drain_until(&mut engine, |c| c.token == ct);
    let cc = cqes.iter().find(|c| c.token == ct).expect("connect CQE");
    assert_eq!(*cc.result.as_ref().expect("established"), 0);

    // Server side accepts (single outstanding SQE, completion-driven re-arm).
    let (sfd, peer) = loop {
        let mut out = Vec::new();
        engine
            .poll(Some(Duration::from_millis(100)), &mut out)
            .expect("poll accept");
        if let Some(accepted) = engine.accept(lfd, Token::accept(0)).expect("accept") {
            break accepted;
        }
    };
    assert!(peer.port() != 0, "kernel filled the peer address");

    // Client writes a payload from a pool slot; server echoes slot-to-slot.
    let payload = b"echo me through the ring";
    let cslot = pool.take().expect("slot");
    pool.slot_mut(cslot)[..payload.len()].copy_from_slice(payload);
    let wt = Token::new(Op::Write, 0, 8, 0);
    engine
        .write(wt, cfd, cslot, payload.len(), 0)
        .expect("write");
    let cqes = drain_until(&mut engine, |c| c.token == wt);
    assert!(cqes
        .iter()
        .any(|c| c.token == wt && matches!(c.result, Ok(n) if n as usize == payload.len())));

    let ssl = pool.take().expect("server slot");
    let rt = Token::new(Op::Read, 0, 9, 0);
    engine.read(rt, sfd, ssl).expect("read");
    let cqes = drain_until(&mut engine, |c| c.token == rt);
    let rc = cqes.iter().find(|c| c.token == rt).expect("read CQE");
    assert_eq!(*rc.result.as_ref().expect("read ok"), payload.len() as u32);
    assert_eq!(&pool.slot(ssl)[..payload.len()], payload);

    // Close the server side through the ring; the client then reads EOF.
    let kt = tok(Op::Close, 10);
    engine.close(kt, sfd).expect("close queued");
    let cqes = drain_until(&mut engine, |c| c.token == kt);
    assert!(cqes.iter().any(|c| c.token == kt && c.result.is_ok()));

    let et = Token::new(Op::Read, 0, 11, 0);
    let eslot = pool.take().expect("eof slot");
    engine.read(et, cfd, eslot).expect("eof read");
    let cqes = drain_until(&mut engine, |c| c.token == et);
    let ec = cqes.iter().find(|c| c.token == et).expect("eof CQE");
    assert_eq!(
        *ec.result.as_ref().expect("eof read ok"),
        0,
        "peer close reads as EOF"
    );

    // SAFETY: test-owned descriptor (client side), engine already closed
    // the peer's.
    unsafe { libc::close(cfd) };
}

#[test]
fn splice_pump_moves_between_fds_via_engine() {
    let (_pool, mut engine) = {
        let pool = BufferPool::new(4, DEFAULT_BUF_SIZE).expect("pool");
        let engine = UringEngine::new(32, Some(&pool), false).expect("ring");
        (pool, engine)
    };
    let pipe = uring_kit::splice::SplicePipe::new().expect("pipe");
    let (a, b) = sockpair();
    let payload = b"zero-copy through the substrate";
    // SAFETY: write to a live pipe.
    unsafe { libc::write(pipe.write_fd(), payload.as_ptr().cast(), payload.len()) };

    let t = Token::new(Op::Splice, 0, 1, 0);
    let t_rev = Token::new(Op::Splice, 0, 1, 1);
    engine
        .splice_pump(t, pipe.read_fd(), t_rev, b)
        .expect("arm pump");
    let cqes = drain_until(&mut engine, |c| c.token == t);
    let moved = *cqes
        .iter()
        .find(|c| c.token == t)
        .expect("pump CQE")
        .result
        .as_ref()
        .expect("pump ok");
    assert_eq!(moved as usize, payload.len());

    let mut buf = [0u8; 64];
    // SAFETY: read from a live socket end.
    let n = unsafe { libc::read(a, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(&buf[..n as usize], payload);
    // SAFETY: test-owned fds.
    unsafe { libc::close(a) };
    // SAFETY: test-owned fds.
    unsafe { libc::close(b) };
}

#[test]
fn relay_ships_completions_off_the_engine_thread() {
    // The dispatch pattern: the engine thread relays CQEs to another
    // thread through the lock-free SPSC ring.
    let (tx, rx) = uring_kit::relay::channel::<u32, 16>();
    let pool = BufferPool::new(4, DEFAULT_BUF_SIZE).expect("pool");
    let mut engine = UringEngine::new(32, Some(&pool), false).expect("ring");
    let (a, b) = sockpair();

    let t = tok(Op::Write, 3);
    engine.write(t, a, 0, 6, 0).expect("write queued");

    std::thread::scope(|s| {
        let handle = s.spawn(move || {
            let mut seen = None;
            for _ in 0..600 {
                if let Some(v) = rx.recv() {
                    seen = Some(v);
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            seen
        });
        let cqes = drain_until(&mut engine, |c| c.token == t);
        for cqe in cqes.iter().filter(|c| c.token == t) {
            tx.send(*cqe.result.as_ref().expect("write ok"))
                .expect("relay");
        }
        let seen = handle.join().expect("consumer thread");
        assert_eq!(seen, Some(6), "completion relayed across threads");
    });

    // SAFETY: test-owned fds.
    unsafe { libc::close(a) };
    // SAFETY: test-owned fds.
    unsafe { libc::close(b) };
}

#[test]
fn poll_returns_pending_style_poll_values() {
    let pool = BufferPool::new(4, DEFAULT_BUF_SIZE).expect("pool");
    let mut engine = UringEngine::new(16, Some(&pool), false).expect("ring");
    let (a, _b) = sockpair();
    // All submissions report Pending; completion arrives via poll.
    assert!(matches!(
        engine.read(tok(Op::Read, 1), a, 0).expect("read"),
        Poll::Pending
    ));
    // SAFETY: test-owned fd.
    unsafe { libc::close(a) };
}

#[test]
fn engine_fakes_implement_the_trait_seam() {
    // The trait exists so consumers can fake the transport; exercise the
    // seam with a deterministic stub.
    struct FakeEngine;
    impl Engine for FakeEngine {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn add_listener(&mut self, _fd: RawFd, _t: Token) -> io::Result<()> {
            Ok(())
        }
        fn add_stream(&mut self, _fd: RawFd, _t: Token) -> io::Result<()> {
            Ok(())
        }
        fn read(&mut self, token: Token, _fd: RawFd, _slot: u32) -> io::Result<Poll> {
            Ok(Poll::Done(u32::from(token.generation())))
        }
        #[allow(clippy::too_many_lines)]
        fn write(
            &mut self,
            _token: Token,
            _fd: RawFd,
            _slot: u32,
            _len: usize,
            _offset: usize,
        ) -> io::Result<Poll> {
            Ok(Poll::Pending)
        }
        fn read_vectored(
            &mut self,
            _token: Token,
            _fd: RawFd,
            _iovs: Box<[libc::iovec]>,
        ) -> io::Result<Poll> {
            Ok(Poll::Pending)
        }
        fn write_vectored(
            &mut self,
            _token: Token,
            _fd: RawFd,
            _iovs: Box<[libc::iovec]>,
        ) -> io::Result<Poll> {
            Ok(Poll::Pending)
        }
        fn close(&mut self, _token: Token, _fd: RawFd) -> io::Result<Poll> {
            Ok(Poll::Pending)
        }
        fn connect(&mut self, _token: Token, _addr: SocketAddr) -> io::Result<(RawFd, Poll)> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "fake"))
        }
        fn connect_unix(
            &mut self,
            _token: Token,
            _path: &std::path::Path,
        ) -> io::Result<(RawFd, Poll)> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "fake"))
        }
        fn accept(&mut self, _lfd: RawFd, _lt: Token) -> io::Result<Option<(RawFd, SocketAddr)>> {
            Ok(None)
        }
        fn splice_pump(
            &mut self,
            _a: Token,
            _afd: RawFd,
            _b: Token,
            _bfd: RawFd,
        ) -> io::Result<()> {
            Ok(())
        }
        fn remove(&mut self, _fd: RawFd) {}
        fn poll(&mut self, _timeout: Option<Duration>, _out: &mut Vec<Cqe>) -> io::Result<()> {
            Ok(())
        }
        fn take_accepted(&mut self, _fd: RawFd) -> Option<SocketAddr> {
            None
        }
    }

    let mut fake = FakeEngine;
    assert_eq!(fake.kind(), "fake");
    assert!(matches!(
        fake.read(tok(Op::Read, 42), 0, 0).expect("fake read"),
        Poll::Done(42)
    ));
}
