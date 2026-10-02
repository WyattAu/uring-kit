//! The engine abstraction — a completion-based transport seam.
//!
//! In vane this trait had two backends (`io_uring` and an epoll emulation);
//! the epoll/mio backend stayed behind as vane-specific runtime policy.
//! uring-kit ships the `io_uring` implementation ([`UringEngine`]) and keeps
//! the trait as the seam consumers use to fake the transport in tests —
//! and as the stable dispatch surface vane's migration will program
//! against.
//!
//! Dispatch pattern (extracted from vane `IO-01`..`IO-05`):
//!
//! 1. submit ops with [`Token`]s (completion routing),
//! 2. drive the ring with [`UringEngine::poll`](crate::uring::UringEngine::poll),
//! 3. match CQEs by token and re-arm persistent state (accept re-arms
//!    after every connection; readiness polls are multishot and re-arm
//!    themselves).

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Duration;

use crate::token::Token;

/// Result of an engine operation that may complete inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Completed immediately with the given byte/fd count.
    Done(u32),
    /// Queued; completion will arrive as a CQE with the same token.
    Pending,
}

/// A completion event.
#[derive(Debug)]
pub struct Cqe {
    /// Token submitted with the operation.
    pub token: Token,
    /// Kernel result: bytes transferred, new fd (accept), or 0.
    pub result: io::Result<u32>,
}

/// Transport engine — owned and driven by a single thread.
pub trait Engine {
    /// Backend name for diagnostics.
    #[must_use]
    fn kind(&self) -> &'static str;

    /// Registers a nonblocking listening socket for accept readiness.
    ///
    /// # Errors
    /// Backend registration failure.
    fn add_listener(&mut self, fd: RawFd, token: Token) -> io::Result<()>;

    /// Registers a connected socket for readiness tracking.
    ///
    /// # Errors
    /// Backend registration failure.
    fn add_stream(&mut self, fd: RawFd, token: Token) -> io::Result<()>;

    /// Queues one registered-buffer read into pool `slot`. The completion
    /// yields bytes read; `0` means EOF.
    ///
    /// # Errors
    /// Submission failure (not `EAGAIN` — that becomes `Pending`).
    fn read(&mut self, token: Token, fd: RawFd, slot: u32) -> io::Result<Poll>;

    /// Queues a write of `slot[0..len]`, resuming from a prior partial
    /// write at `offset`.
    ///
    /// # Errors
    /// Submission failure (not `EAGAIN`).
    fn write(
        &mut self,
        token: Token,
        fd: RawFd,
        slot: u32,
        len: usize,
        offset: usize,
    ) -> io::Result<Poll>;

    /// Queues a vectored read into caller-owned iovecs. The iovec array is
    /// moved into engine storage for the op lifetime; the *buffers* behind
    /// it must remain valid until the token's CQE is consumed (crate-level
    /// ownership contract).
    ///
    /// # Errors
    /// Submission failure (not `EAGAIN`).
    fn read_vectored(
        &mut self,
        token: Token,
        fd: RawFd,
        iovs: Box<[libc::iovec]>,
    ) -> io::Result<Poll>;

    /// Queues a vectored write from caller-owned iovecs (same lifetime
    /// contract as [`Engine::read_vectored`]).
    ///
    /// # Errors
    /// Submission failure (not `EAGAIN`).
    fn write_vectored(
        &mut self,
        token: Token,
        fd: RawFd,
        iovs: Box<[libc::iovec]>,
    ) -> io::Result<Poll>;

    /// Queues `close(2)` of `fd`; the completion reports `Ok(0)`. The fd
    /// must not be reused until the CQE is consumed.
    ///
    /// # Errors
    /// Submission failure.
    fn close(&mut self, token: Token, fd: RawFd) -> io::Result<Poll>;

    /// Starts a nonblocking `connect(2)`; the completion is a CQE where
    /// `result == Ok(0)` means established.
    ///
    /// # Errors
    /// Socket creation or connect submission failure.
    fn connect(&mut self, token: Token, addr: SocketAddr) -> io::Result<(RawFd, Poll)>;

    /// Starts a nonblocking Unix-domain `connect(2)` to `path`.
    ///
    /// # Errors
    /// Socket creation or connect submission failure.
    fn connect_unix(&mut self, token: Token, path: &std::path::Path) -> io::Result<(RawFd, Poll)>;

    /// Attempts an accept on a registered listener; `Ok(Some(..))`
    /// completes inline, `Ok(None)` waits for the connection to materialize
    /// (exactly one accept SQE is outstanding per listener at all times).
    ///
    /// # Errors
    /// Fatal (non-`EAGAIN`) accept error.
    fn accept(&mut self, lfd: RawFd, ltoken: Token) -> io::Result<Option<(RawFd, SocketAddr)>>;

    /// Starts a bidirectional zero-copy splice pump between two streams.
    /// Completions on either token report bytes moved; `Ok(0)` signals EOF
    /// for that direction.
    ///
    /// # Errors
    /// Submission failure.
    fn splice_pump(&mut self, a: Token, afd: RawFd, b: Token, bfd: RawFd) -> io::Result<()>;

    /// Removes a descriptor's tracked state (before the caller closes it).
    fn remove(&mut self, fd: RawFd);

    /// Drives the backend, filling `out` with completions. Blocks up to
    /// `timeout` (or indefinitely when `None`).
    ///
    /// # Errors
    /// Event-loop failure (unrecoverable; the owner should tear down).
    fn poll(&mut self, timeout: Option<Duration>, out: &mut Vec<Cqe>) -> io::Result<()>;

    /// Pops the peer address of an accepted connection reported by an
    /// accept completion.
    fn take_accepted(&mut self, fd: RawFd) -> Option<SocketAddr>;
}
