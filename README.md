# uring-kit

Reusable io_uring socket substrate for Rust — the shared kernel-bypass
transport layer of the WyattAu estate, extracted from the
[vane](https://github.com/WyattAu/vane) edge proxy. **Linux-only, by
declaration** (L1 substrate: everything above it may assume this layer
works).

- **Ring lifecycle**: one `io_uring` instance per thread, optional
  `SQPOLL` (kernel thread drains the SQ — zero syscalls on the hot path),
  bounded `poll` waits via `IORING_ENTER_EXT_ARG` with a fallback for
  older kernels.
- **Registered buffer pools**: pre-allocated, stable-address slots handed
  to the kernel via `IORING_REGISTER_BUFFERS`; `READ_FIXED`/`WRITE_FIXED`
  move bytes directly between kernel and pool — no per-op mapping, no
  hot-path allocation.
- **Socket ops**: accept (single outstanding SQE, completion-driven
  re-arm), connect (INET + Unix, submission-safe owned sockaddrs),
  fixed-buffer read/write with partial-write resume, vectored read/write,
  `close`, multishot `POLL_ADD` readiness.
- **Zero-copy splice**: `splice(2)` + `SPLICE_F_MOVE` through a kernel
  pipe — L4 passthrough bytes never enter user space.
- **Feature probing**: kernel version (`uname`), opcode support
  (`IORING_REGISTER_PROBE`), `SQPOLL` permission, ring params features —
  degrade gracefully instead of guessing.
- **Completion dispatch**: packed `Token` routing (`op|gen|slot|aux`)
  plus a cacheline-padded, lock-free SPSC relay for shipping completions
  off the engine thread (loom model-checked).
- **Lint posture**: `unsafe` is inherent here (FFI substrate) and *not*
  forbidden — instead every unsafe block carries a `// SAFETY:`
  justification (`clippy::undocumented_unsafe_blocks = deny`,
  `unsafe_op_in_unsafe_fn = deny`) and the crate docs audit every site.

## Install

```toml
[dependencies]
uring-kit = "0.1"
```

Any non-Linux target fails to compile with an explicit
`compile_error!` — the platform is part of the contract, not an
accident.

## Example

```no_run
# fn main() -> std::io::Result<()> {
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use uring_kit::engine::Engine as _;
use uring_kit::{BufferPool, DEFAULT_BUF_SIZE, Op, Token, UringEngine};

// One pool + ring per thread; slots are registered as fixed buffers.
let mut pool = BufferPool::new(1024, DEFAULT_BUF_SIZE).expect("pool");
let mut engine = UringEngine::new(256, Some(&pool), false)?;

let addr: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
let listener = uring_kit::net::tcp_listener(addr, false, 128)?;
engine.add_listener(listener.as_raw_fd(), Token::accept(0))?;

// Dial an upstream; the CQE carries Ok(0) when established.
let target: SocketAddr = "10.0.0.1:5432".parse().expect("addr");
let (fd, _poll) = engine.connect(Token::new(Op::Connect, 0, 1, 0), target)?;

// Read into pool slot 0; the completion reports bytes read (0 = EOF).
let slot = pool.take().expect("slot");
let _ = engine.read(Token::new(Op::Read, slot as u32, 1, 0), fd, slot)?;
# let _ = pool; let _ = listener;
# Ok(())
# }
```

Drive completions on your thread (or relay them with
`uring_kit::relay::channel`):

```rust,ignore
let mut out = Vec::new();
engine.poll(Some(Duration::from_millis(50)), &mut out)?;
for cqe in out {
    match cqe.token.op() {
        Op::Accept => { /* engine.accept(lfd, token) yields (fd, peer) */ }
        Op::Read   => { /* cqe.result: bytes read, 0 = EOF */ }
        _ => {}
    }
}
```

## Provenance

Extracted (one-directional copy + genericize, commit
`a495bf63bfc5b37fd99000c4a4afc9e8b4a1c5b6` of
[WyattAu/vane](https://github.com/WyattAu/vane)):

| uring-kit module | vane-core source | Changes |
|------------------|------------------|---------|
| `uring` | `vane-kernel/src/engine/uring.rs` | op enum genericized (downstream/upstream → `Read`/`Write`), added vectored ops + `close`, engine-trait decoupling |
| `buffer` | `vane-kernel/src/buffer.rs` | arbitrary slot size (was pinned to 4096) |
| `splice` | `vane-kernel/src/splice.rs` | owned `SplicePipe` with `Drop` (vane leaked the thread-local pipe), bounded destination spin |
| `token` | `vane-kernel/src/token.rs` | direction-neutral op set, `Close` op added |
| `net` | `vane-kernel/src/net.rs` | unchanged (generic socket setup) |
| `relay` | `vane-kernel/src/spsc.rs` | renamed for substrate role; loom double added |
| `probe` | (new) | vane probed implicitly via ring-creation failures; made explicit |

Still in vane (deliberately not extracted): `worker.rs` (thread-per-core
runtime), `slab.rs` (session slab), `handler.rs`, `h2/`, `mio_engine.rs`
(fallback backend), proxy routing/config. vane's migration to consume
this crate is tracked in its own repository — this extraction does not
modify vane.

## Platform

Linux kernel ≥ 5.1 (io_uring baseline with registered buffers). Use
[`Probe::detect`](https://docs.rs/uring-kit) to check what the running
kernel actually supports (opcodes, `SQPOLL`, multishot poll, `EXT_ARG`).
Several distributions seccomp-filter io_uring — never assume; probe.

## Safety

io_uring is an FFI interface: this crate contains inherent `unsafe` and
declares it. `unsafe_code` is not forbidden; instead:

- every `unsafe` block carries a `// SAFETY:` justification
  (`clippy::undocumented_unsafe_blocks = deny`),
- `unsafe_op_in_unsafe_fn = deny`,
- the crate-level `# Safety` docs audit every site,
- `unwrap`, `panic`, and `indexing_slicing` are denied in library code.

The ownership contract is the one vane's worker loop upheld: **buffers
and fds passed to a submission must remain valid until the token's CQE
is consumed.**

## Development

```sh
cargo test                       # unit + integration (needs Linux + io_uring)
cargo test --features loom --test loom_relay   # concurrency model checks
cargo bench                      # criterion: ring round-trip, pool, splice, relay
```

CI runs the estate Tier-A gate matrix (check/test/clippy/fmt/deny/vet/
coverage ≥ 90%/semver) plus dedicated loom and miri jobs — see
`.github/workflows/ci.yml`.

## License

MIT OR Apache-2.0
