//! uring-kit — the reusable `io_uring` socket substrate of the `WyattAu` estate
//! (L1: kernel-bypass transport, Linux platform-declared).
//!
//! Extracted from `vane-core` (the `vane-kernel` crate of the
//! [vane](https://github.com/WyattAu/vane) edge proxy) at commit
//! `a495bf63bfc5b37fd99000c4a4afc9e8b4a1c5b6` and genericized: everything
//! vane-specific (HTTP handler, h2, routing, worker runtime, session slab,
//! mio fallback) stayed in vane; what shipped here is the transport core.
//!
//! # Surface
//!
//! - [`UringEngine`] — one ring per thread, optional `SQPOLL`, fixed
//!   registered buffers: `ReadFixed`/`WriteFixed` straight into a
//!   [`BufferPool`], multishot `PollAdd` readiness, single-shot accept with
//!   completion-driven re-arm, nonblocking `connect` (INET + Unix),
//!   vectored read/write, `Close`, and a zero-copy L4 splice pump.
//! - [`BufferPool`] — stable-address, pre-allocated slots registered with
//!   the kernel (`IORING_REGISTER_BUFFERS`); the hot path never mallocs.
//! - [`splice`] — `splice(2)` + `SPLICE_F_MOVE` pumping through a kernel
//!   pipe: request bytes never enter user space.
//! - [`probe`] — kernel/feature detection: ring availability, opcode
//!   support (`IORING_REGISTER_PROBE`), SQPOLL permission, kernel version.
//! - [`relay`] — lock-free SPSC completion relay (cacheline-padded,
//!   zero `SeqCst`) for handing CQEs off the engine thread; loom
//!   model-checked.
//! - [`token`] — packed completion tokens (`op | gen | slot | aux`) that
//!   route CQEs back to their issuer.
//! - [`net`] — listener/socket setup helpers (`SO_REUSEPORT` per-core
//!   accept, `TCP_NODELAY`, keepalive tuning).
//!
//! # Quickstart
//!
//! ```no_run
//! # fn main() -> std::io::Result<()> {
//! use std::net::SocketAddr;
//! use std::os::fd::AsRawFd;
//! use uring_kit::engine::Engine as _;
//! use uring_kit::{BufferPool, DEFAULT_BUF_SIZE, Op, Token, UringEngine};
//!
//! // One pool + ring per thread; slots are registered as fixed buffers.
//! let mut pool = BufferPool::new(1024, DEFAULT_BUF_SIZE).expect("pool");
//! let mut engine = UringEngine::new(256, Some(&pool), false)?;
//!
//! let addr: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
//! let listener = uring_kit::net::tcp_listener(addr, false, 128)?;
//! engine.add_listener(listener.as_raw_fd(), Token::accept(0))?;
//!
//! // Dial an upstream; the CQE carries `Ok(0)` when established.
//! let target: SocketAddr = "10.0.0.1:5432".parse().expect("addr");
//! let (fd, _poll) = engine.connect(Token::new(Op::Connect, 0, 1, 0), target)?;
//!
//! // Read into pool slot 0; the completion reports bytes read (0 = EOF).
//! let slot = pool.take().expect("slot");
//! let _ = engine.read(Token::new(Op::Read, slot as u32, 1, 0), fd, slot)?;
//! # let _ = pool; let _ = listener;
//! # Ok(())
//! # }
//! ```
//!
//! # Ownership contract
//!
//! The engine is completion-based and single-owner per ring: the caller
//! submits an operation with a [`Token`]; buffers and file descriptors
//! passed to a submission **must remain valid until that token's CQE has
//! been consumed** by [`UringEngine::poll`]. This is the same contract
//! vane's worker loop upheld at each call site; it is what keeps SQE
//! construction free of per-op copies. The engine additionally owns and
//! frees op-lifetime storage itself where it can (connect sockaddrs,
//! vectored-iovec arrays, accept sockaddr scratch).
//!
//! # Platform
//!
//! Linux only, by declaration: the whole library is `#[cfg(target_os =
//! "linux")]` and every other target fails to compile with a
//! [`compile_error!`] explaining why. [`probe`] reports what the running
//! kernel actually supports.
//!
//! # Safety
//!
//! This crate contains inherent `unsafe` (FFI to the `io_uring` uAPI, raw
//! pointers into registered buffers, sockaddr ABI serialization).
//! `unsafe_code` is therefore *not* forbidden crate-wide — the documented
//! posture is: every `unsafe` block carries a `// SAFETY:` justification
//! (enforced by `clippy::undocumented_unsafe_blocks = deny`), and every
//! site is audited here:
//!
//! 1. **`UringEngine::push` — SQ ring push**
//!    (`uring.rs`). *Invariant:* each entry is pushed exactly once and its
//!    completion is consumed on the same thread (`UringEngine` is
//!    single-owner, `Send`); the io-uring crate requires unsafe for SQ
//!    access. On a full SQ the loop submits and retries, so no entry is
//!    dropped or duplicated.
//! 2. **Buffer registration** (`UringEngine::new`). *Invariant:* the
//!    iovecs point at [`BufferPool`] slots, which are heap allocations
//!    with stable addresses that live as long as the engine's `slot_bases`
//!    (the pool is borrowed only for the registration, and the caller keeps
//!    it alive — documented in `new`); the kernel writes only within
//!    `iov_len` for `buf_index = slot` ops the engine itself issues.
//! 3. **`ReadFixed`/`WriteFixed` pointer arithmetic**
//!    (`read`/`write`). *Invariant:* `slot` indexes the registered pool
//!    (caller's contract, `debug_assert`ed) and `offset` is clamped by the
//!    caller to the slot length; `ptr.add(offset)` therefore stays inside
//!    the registered iovec the kernel already bounds-checks by
//!    `buf_index`.
//! 4. **`connect_addr_boxed` — sockaddr serialization**. *Invariant:* the
//!    `sockaddr_storage` is zeroed then fully initialized for the active
//!    family (v4/v6 branches write matching layouts); the box's heap
//!    address is stable and kept in `connect_addrs` until the op's CQE is
//!    observed (`io_uring` copies the sockaddr at *submit* time — a stack
//!    sockaddr would dangle between push and submit).
//! 5. **Unix connect storage copy** (`connect_unix`). *Invariant:*
//!    `copy_nonoverlapping` of `sa.len()` bytes (clamped to the storage
//!    size) from socket2's valid `SockAddr` into zeroed owned storage,
//!    which then lives in `connect_addrs` per (4).
//! 6. **`parse_sockaddr` — accept peer decoding.** *Invariant:* the 128-
//!    byte scratch buffer the kernel filled is read as `sockaddr_storage`
//!    and the family-selected variant (`sockaddr_in` / `sockaddr_in6`) is
//!    exactly what the kernel wrote for that `ss_family`.
//! 7. **`UringEngine: Send`**. *Invariant:* all state is thread-confined
//!    (raw slot pointers are engine-private; the kernel consumes SQEs on
//!    the submitting thread, or via the SQPOLL kernel thread which is
//!    bound to the same ring memory).
//! 8. **Accept scratch pointers** (`arm_accept`). *Invariant:* the
//!    sockaddr output buffer and length are boxed engine state, stable
//!    across moves, alive until the accept CQE is consumed on this thread.
//! 9. **Vectored ops** (`read_vectored`/`write_vectored`). *Invariant:*
//!    the caller-built iovec array is boxed into engine storage for the op
//!    lifetime; buffer validity until the CQE is the documented caller
//!    contract (crate-level *Ownership contract*).
//! 10. **`splice::pump`** — `splice(2)` FFI. *Invariant:* all fds are
//!     caller-live for the call; null offsets mean "current position",
//!     which is the documented behavior for sockets/pipes; flags keep the
//!     operation nonblocking with page moves.
//! 11. **`net` helpers** — `setsockopt` with correctly sized option
//!     values, one `from_raw_fd` ownership transfer of a live socket, and
//!     `StreamFd`'s single `close` on drop.
//! 12. **`relay::SpscRing`** — slot access is guarded by the sequence
//!     protocol: `sequence == pos` means the slot is empty and exclusively
//!     claimable by the single producer; `sequence == pos + 1` means a
//!     value was published (release) and the single consumer owns the take.
//!     The full argument is in `relay.rs` and exhaustively model-checked
//!     under loom (`tests/loom_relay.rs` + `relay_model` double).
//!
//! # Provenance
//!
//! | | |
//! |---|---|
//! | Extracted from | `vane` repo, crate `vane-kernel` (lib name `vane_core`) |
//! | Commit | `a495bf63bfc5b37fd99000c4a4afc9e8b4a1c5b6` |
//! | Modules | `engine/uring.rs`, `buffer.rs`, `splice.rs`, `token.rs`, `net.rs`, `spsc.rs` (→ [`relay`]) |
//! | Left in vane | `worker.rs`, `slab.rs`, `handler.rs`, `h2/`, `engine/mio_engine.rs`, proxy config/routing |
//!
//! The extraction is one-directional (copy + genericize); vane's migration
//! to consume this crate is tracked in its own repository.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "uring-kit requires Linux: the io_uring uAPI is a Linux kernel interface \
     and this crate declares the Linux platform (see README § Platform)."
);

#[cfg(target_os = "linux")]
pub mod buffer;
#[cfg(target_os = "linux")]
pub mod engine;
#[cfg(target_os = "linux")]
pub mod net;
#[cfg(target_os = "linux")]
pub mod probe;
#[cfg(target_os = "linux")]
pub mod relay;
#[cfg(all(target_os = "linux", feature = "loom"))]
pub mod relay_model;
#[cfg(target_os = "linux")]
pub mod splice;
#[cfg(target_os = "linux")]
pub mod token;
#[cfg(target_os = "linux")]
pub mod uring;

#[cfg(target_os = "linux")]
pub use buffer::{BufferPool, DEFAULT_BUF_SIZE, DEFAULT_POOL_SIZE};
#[cfg(target_os = "linux")]
pub use engine::{Cqe, Engine, Poll};
#[cfg(target_os = "linux")]
pub use net::{set_keepalive, set_nodelay, shutdown_write, tcp_listener, StreamFd};
#[cfg(target_os = "linux")]
pub use probe::Probe;
#[cfg(target_os = "linux")]
pub use relay::{channel, SpscReceiver, SpscRing, SpscSender};
#[cfg(target_os = "linux")]
pub use splice::{pump, PumpResult, SplicePipe};
#[cfg(target_os = "linux")]
pub use token::{Op, Token};
#[cfg(target_os = "linux")]
pub use uring::UringEngine;
