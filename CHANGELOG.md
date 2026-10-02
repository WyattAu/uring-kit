# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [0.1.0] - 2026-10-02

### Added

- Initial release: reusable io_uring socket substrate extracted from
  vane-core (`vane-kernel`) at commit
  `a495bf63bfc5b37fd99000c4a4afc9e8b4a1c5b6`.
- `UringEngine`: per-thread ring lifecycle (creation, registered-buffer
  registration, teardown), SQ/CQ management, batched submission with
  SQ-full backpressure loop, bounded `poll` waits (`IORING_ENTER_EXT_ARG`
  with plain-wait fallback), optional `SQPOLL`.
- Socket operations: multishot `POLL_ADD` readiness, single-shot accept
  with completion-driven re-arm (peer address materialized per
  connection), INET/Unix nonblocking `connect` with op-lifetime owned
  sockaddr storage, `READ_FIXED`/`WRITE_FIXED` with partial-write resume,
  vectored `READV`/`WRITEV` with engine-owned iovec parking, `CLOSE`.
- `BufferPool`: stable-address fixed slots (`IORING_REGISTER_BUFFERS`
  semantics), LIFO slot free list, arbitrary (fixed-at-construction)
  slot size.
- `splice`: zero-copy `splice(2)` + `SPLICE_F_MOVE` pump through a kernel
  pipe; owned `SplicePipe` resource (fixes vane-core's leaked
  thread-local pipe fds) and bounded destination-backpressure spin
  (fixes a potential live-lock against stalled peers).
- `token`: packed 64-bit completion tokens (`op:8|gen:16|slot:24|aux:16`)
  with direction-neutral op set (`Accept`/`Read`/`Write`/`Connect`/
  `Close`/`Splice`).
- `probe`: kernel/feature detection — ring availability, opcode support
  via `IORING_REGISTER_PROBE`, `SQPOLL` permission, `EXT_ARG`/`NODROP`
  params features, `uname` version parsing.
- `relay`: cacheline-padded lock-free SPSC completion relay (zero
  `SeqCst`, acquire/release handoff) with loom model-checking
  (`tests/loom_relay.rs` real-ring interleavings + `relay_model`
  exhaustive protocol double).
- Platform declaration: Linux-only; every other target fails compilation
  with an explanatory `compile_error!`.
- Tests: kernel round-trips (socketpair echo, TCP echo through the ring,
  splice pump, close/EOF semantics, SQPOLL-when-permitted), feature
  probing, buffer pool, token packing, relay concurrency; criterion
  benches (op round-trip, pool take/release, splice throughput, relay
  handoff).
- Estate Tier-A gates: lints (deny `undocumented_unsafe_blocks`,
  `unsafe_op_in_unsafe_fn`, `unwrap_used`, `panic`, `indexing_slicing`,
  `missing_docs` — documented deviation from `forbid(unsafe_code)`;
  unsafe is inherent to the FFI substrate and every block carries a
  `// SAFETY:` audit), cargo-deny, cargo-vet, loom + miri CI jobs.
