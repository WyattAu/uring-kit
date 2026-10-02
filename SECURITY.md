# Security Policy — uring-kit

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Report privately via [GitHub security advisories] for this repository, or
email **wyatt_au@protonmail.com**. Do **not** open a public issue for
security reports.

You will receive an acknowledgement within **72 hours**. Coordinated
disclosure: we ask for up to 90 days before public disclosure while a
patch ships.

[GitHub security advisories]:
    https://github.com/WyattAu/uring-kit/security/advisories/new

## Threat model — io_uring attack surface

Reference: STRIDE. Scope: the crate's public API (`UringEngine`,
`BufferPool`, `splice`, `relay`, `probe`, `token`) across the kernel
boundary. Trust boundaries: (1) the kernel's io_uring implementation and
its uAPI, (2) file descriptors handed in by the embedder, (3) the
dependency tree (`io-uring`, `libc`, `socket2`), (4) other threads in the
host process.

This crate sits at the bottom of the estate stack and *drives a kernel
bypass interface*. io_uring has a long history of CVEs (inline poll
abuse, registered-file lifetime confusion, `io_uring_register` races, spoofed
SQE padding leaks) and is seccomp-filtered or disabled entirely on
several distributions and in container sandboxes (Docker's default
profile, Google's production infra). Treat the ring itself as a
privileged capability.

### Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Memory safety of the engine thread | A malformed SQE (bad `buf_index`, dangling sockaddr) writing outside a registered pool slot |
| A2 | fd integrity | A `close` op completing while the embedder has already reused the fd number for a different socket |
| A3 | Op-lifetime pointer stability | A connect sockaddr or vectored-iovec array freed before the kernel copied it at submit time |
| A4 | Availability of the poll loop | A full SQ with no progress, or an unbounded spin against a backpressured splice destination |
| A5 | Cross-thread completion integrity | A completion lost or duplicated in the SPSC relay |

### STRIDE analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | SQE referencing an unregistered/out-of-range `buf_index` | Tampering | `read`/`write` | `slot_ptr` bounds-map against the registered base table (unregistered engines get a null pointer and the kernel rejects the op); `BufferPool::release` debug-asserts slot range; registration happens once in `new` | `engine_without_pool_has_no_fixed_buffers`, `write_then_read_roundtrip`, `ring_lifecycle_pool_registration_and_teardown` |
| T2 | Sockaddr/iovec storage freed before kernel submit | Tampering (UAF) | `connect`, `connect_unix`, `read_vectored`, `write_vectored` | op-lifetime boxes parked in engine maps (`connect_addrs`, `vec_iovs`), released only when the CQE is observed; documented embedder contract for iovec *buffers* | `connect_refused_completes_with_error`, `connect_establishes_to_local_listener`, `vectored_write_then_read_roundtrip` |
| T3 | fd reuse between submission and completion | Confused deputy | all ops | documented ownership contract: fd must stay valid until the CQE; `close` op exists so embedders close through the ring; accept fds are returned before re-arm | `close_op_completes`, `echo_round_trip_over_tcp_with_registered_buffers` |
| T4 | Malicious/kernel-bug CQE floods or bogus `user_data` | Spoofing | `poll` | tokens are decoded defensively (foreign bits fall back to `Splice`, never panic); unknown-token CQEs are surfaced, not swallowed | `foreign_bits_fall_back_to_splice` |
| T5 | Live-lock against a stalled splice peer | DoS | `splice::pump` | destination-EAGAIN spin is bounded (`DEST_SPIN_BUDGET`); the round returns a partial `Moved` and the pump is re-armed by readiness — vane's unbounded spin was deliberately not carried over | `splice_moved_and_eof_paths`, `splice_pump_moves_between_fds_via_engine` |
| T6 | Relay race: lost/duplicated/out-of-order completion | Tampering | `relay::SpscRing` | acquire/release sequence protocol, zero `SeqCst`; exhaustively model-checked under loom (double) plus interleaving tests on the real ring | `model_no_loss_no_duplication_fifo`, `model_backpressure_never_crosses_capacity`, `real_ring_handoff_order_under_all_interleavings` |
| T7 | Kernel without io_uring (seccomp-filtered) assumed available | DoS (config) | `UringEngine::new` | construction is fallible; `probe::Probe::detect()` is the sanctioned availability check with opcode-level detail — callers must degrade gracefully | `probe_detects_the_test_kernel`, `detect_reports_capabilities` |
| T8 | `SQPOLL` provisioned without permission | Elevation (config) | `UringEngine::new` | SQPOLL ring creation is fallible and probed (`Probe::sqpoll_permitted`); the documented fallback is a plain ring — no privilege assumptions | `sqpoll_construction_when_permitted` |
| T9 | Unbounded accept SQE accumulation | DoS | `add_listener`/`accept` | exactly one accept SQE outstanding per listener, re-armed strictly on completion | `accept_flow_materializes_connection` |

### Repudiation

Not applicable — a transport substrate has no audit surface. Callers
needing audit trails should instrument at their layer.

### Out of scope

- Kernel bugs in io_uring itself: this crate drives the uAPI faithfully
  (every SQE field is kernel-documented) but cannot defend the kernel
  from itself. Run supported kernels; keep seccomp policy in mind when
  embedding in multi-tenant environments.
- TLS, HTTP, or any payload semantics — the layer is byte-transparent.
- Embedder violations of the ownership contract (closing an fd or
  freeing a buffer with ops in flight): documented, `debug_assert`ed
  where possible, but not preventable at this layer.

### Residual risks

- **R1 (Medium, accepted):** the embedder owns fd/buffer lifetimes
  across submission→completion; the crate cannot statically verify the
  contract (T3). Mitigation: single-owner engine design, `close` op,
  documented contract, and the SAFETY audit in lib.rs.
- **R2 (Low, accepted):** `ECANCELED` completions are intentionally
  suppressed (listener teardown semantics carried over from vane);
  embedders that cancel ops themselves should account for silent CQEs.
- **R3 (Low, accepted):** `splice::pump`'s shared per-thread staging pipe
  is process-visible state (pipe fds); capacity is kernel-default (64
  KiB) — high-fanout embedders wanting dedicated buffers per direction
  should use `SplicePipe` + `pump_via` explicitly.
