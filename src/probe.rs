//! Kernel version probing and `io_uring` feature detection.
//!
//! vane discovered capabilities implicitly (ring creation failures, the
//! `IORING_ENTER_EXT_ARG` fallback in `poll`); this module makes the probe
//! explicit and reusable: does the running kernel have `io_uring` at all,
//! which opcodes does it implement (`IORING_REGISTER_PROBE`), is `SQPOLL`
//! permitted for this user, and what version is it.
//!
//! Kernel milestones this crate cares about (runtime-verified, never
//! assumed):
//!
//! | Kernel | Capability |
//! |--------|------------|
//! | 5.1    | `io_uring` baseline, `IORING_REGISTER_BUFFERS`, `READ_FIXED`/`WRITE_FIXED` |
//! | 5.5    | `IORING_OP_CLOSE` |
//! | 5.7    | `IORING_OP_SPLICE` (this crate pumps with `splice(2)` + readiness instead — backend-agnostic) |
//! | 5.11   | unprivileged-friendly `SQPOLL` (still gated by root/`io_uring_group`) |
//! | 5.13   | multishot `POLL_ADD` (`multi(true)`) |
//! | 5.19   | `IORING_ENTER_EXT_ARG` (bounded `poll` waits via timespec) |
//!
//! Security note: several distributions restrict or seccomp-filter
//! `io_uring` (it is a recurring kernel attack surface — see SECURITY.md).
//! [`Probe::detect`] is the sanctioned availability check: callers should
//! degrade gracefully when it reports `io_uring` unavailable rather than
//! assuming kernel features from version strings alone.

use std::io;
use std::sync::OnceLock;

use io_uring::register::Probe as UringProbe;

/// Opcode set this crate drives, with stable names for diagnostics.
pub const KNOWN_OPCODES: &[(&str, u8)] = &[
    ("ACCEPT", io_uring::opcode::Accept::CODE),
    ("CONNECT", io_uring::opcode::Connect::CODE),
    ("READ_FIXED", io_uring::opcode::ReadFixed::CODE),
    ("WRITE_FIXED", io_uring::opcode::WriteFixed::CODE),
    ("READV", io_uring::opcode::Readv::CODE),
    ("WRITEV", io_uring::opcode::Writev::CODE),
    ("CLOSE", io_uring::opcode::Close::CODE),
    ("POLL_ADD", io_uring::opcode::PollAdd::CODE),
    ("RECV", io_uring::opcode::Recv::CODE),
    ("SEND", io_uring::opcode::Send::CODE),
];

/// Capabilities of the running kernel's `io_uring` implementation.
#[derive(Debug, Clone)]
pub struct Probe {
    /// `uname(2)` release string (e.g. `"6.12.4-arch1-1"`).
    kernel_release: String,
    /// Parsed `(major, minor)` of the release string.
    kernel_version: (u32, u32),
    /// `KNOWN_OPCODES` support bitmap, index-aligned.
    opcode_support: Vec<bool>,
    /// A SQPOLL ring could be created (root / `io_uring_group` / permissive
    /// kernel).
    sqpoll_permitted: bool,
    /// Ring params advertised `EXT_ARG` (bounded waits).
    ext_arg: bool,
    /// Ring params advertised `NODROP`.
    nodrop: bool,
}

impl Probe {
    /// Probes the running kernel: builds a scratch ring, asks it for opcode
    /// support, attempts a SQPOLL ring, and reads `uname(2)`.
    ///
    /// # Errors
    /// `io_uring` is unavailable (pre-5.1 kernel, seccomp-filtered, or
    /// `vm.max_user_instances` exhausted) — callers should fall back to a
    /// readiness-based transport.
    pub fn detect() -> io::Result<Self> {
        let ring = io_uring::IoUring::new(4)?;
        let mut uprobe = UringProbe::new();
        ring.submitter().register_probe(&mut uprobe)?;
        let opcode_support = KNOWN_OPCODES
            .iter()
            .map(|&(_, code)| uprobe.is_supported(code))
            .collect();
        let params = ring.params();
        let ext_arg = params.is_feature_ext_arg();
        let nodrop = params.is_feature_nodrop();
        drop(ring);
        let sqpoll_permitted = Self::sqpoll_available();
        let (kernel_release, kernel_version) = kernel_info();
        Ok(Self {
            kernel_release,
            kernel_version,
            opcode_support,
            sqpoll_permitted,
            ext_arg,
            nodrop,
        })
    }

    /// `uname(2)` release string.
    #[must_use]
    pub fn kernel_release(&self) -> &str {
        &self.kernel_release
    }

    /// Parsed `(major, minor)` kernel version.
    #[must_use]
    pub fn kernel_version(&self) -> (u32, u32) {
        self.kernel_version
    }

    /// True when the detected kernel version is at least `major.minor`.
    #[must_use]
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        let (m, n) = self.kernel_version;
        (m, n) >= (major, minor)
    }

    /// Reports support for one of [`KNOWN_OPCODES`]' codes (unknown codes
    /// read as unsupported — we only claim what we probed).
    #[must_use]
    pub fn supports_opcode(&self, code: u8) -> bool {
        for (&(_, c), &supported) in KNOWN_OPCODES.iter().zip(&self.opcode_support) {
            if c == code {
                return supported;
            }
        }
        false
    }

    /// Diagnostic name/support pairs (`("READ_FIXED", true)` ...).
    #[must_use]
    pub fn opcode_report(&self) -> Vec<(&'static str, bool)> {
        KNOWN_OPCODES
            .iter()
            .zip(&self.opcode_support)
            .map(|(&(name, _), &ok)| (name, ok))
            .collect()
    }

    /// `SQPOLL` is permitted for this user.
    #[must_use]
    pub fn sqpoll_permitted(&self) -> bool {
        self.sqpoll_permitted
    }

    /// `IORING_ENTER_EXT_ARG` advertised (bounded `poll` timeouts).
    #[must_use]
    pub fn ext_arg(&self) -> bool {
        self.ext_arg
    }

    /// `NODROP` advertised (completions are not dropped under pressure).
    #[must_use]
    pub fn nodrop(&self) -> bool {
        self.nodrop
    }

    /// Fixed-buffer reads (`READ_FIXED` + `IORING_REGISTER_BUFFERS`) — the
    /// crate's core fast path.
    #[must_use]
    pub fn supports_registered_buffers(&self) -> bool {
        self.supports_opcode(io_uring::opcode::ReadFixed::CODE)
            && self.supports_opcode(io_uring::opcode::WriteFixed::CODE)
    }

    /// Multishot readiness (`POLL_ADD` with `multi`) — kernel 5.13+.
    #[must_use]
    pub fn supports_multishot_poll(&self) -> bool {
        self.at_least(5, 13) && self.supports_opcode(io_uring::opcode::PollAdd::CODE)
    }

    /// Attempts to build a SQPOLL ring; caches the answer process-wide
    /// (the permission does not change under a running process).
    ///
    /// # Errors
    /// Propagates ring creation failure when even a plain ring is
    /// unavailable.
    fn sqpoll_available() -> bool {
        static SQPOLL: OnceLock<bool> = OnceLock::new();
        *SQPOLL.get_or_init(|| {
            // SAFETY: none — this is a safe builder call; the type annotation
            // disambiguates the crate's generic `IoUring<S, C>` defaults.
            let build: io::Result<io_uring::IoUring> =
                io_uring::IoUring::builder().setup_sqpoll(2_000).build(4);
            build.is_ok()
        })
    }
}

/// Reads `uname(2)` and parses the leading `major.minor` of the release.
fn kernel_info() -> (String, (u32, u32)) {
    // SAFETY: utsname fills a caller-provided buffer; the release field is
    // NUL-terminated by the kernel.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: pointer to our own utsname storage.
    if unsafe { libc::uname(std::ptr::addr_of_mut!(uts)) } != 0 {
        return (String::new(), (0, 0));
    }
    // SAFETY: release is a NUL-terminated char array from uname.
    let release: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    let release = release.to_string_lossy().into_owned();
    let version = parse_kernel_version(&release);
    (release, version)
}

/// Parses `"6.12.4-arch1-1"` into `(6, 12)`; unparseable input yields `(0, 0)`.
#[must_use]
pub fn parse_kernel_version(release: &str) -> (u32, u32) {
    let digits = |s: &str| -> Option<u32> {
        let num: String = s.chars().take_while(char::is_ascii_digit).collect();
        num.parse().ok()
    };
    let mut parts = release.split('.');
    match (parts.next().and_then(digits), parts.next().and_then(digits)) {
        (Some(major), Some(minor)) => (major, minor),
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_reports_capabilities() {
        let probe = Probe::detect().expect("io_uring available in test env");
        assert!(probe.kernel_version().0 >= 5, "io_uring needs >= 5.1");
        assert!(probe.at_least(5, 1));
        assert!(
            probe.supports_registered_buffers(),
            "fixed buffers are the crate's core path: {:?}",
            probe.opcode_report()
        );
        // Accept/connect/close/readv/writev are ancient; a kernel that
        // boots this test has them.
        for (name, ok) in probe.opcode_report() {
            if matches!(name, "ACCEPT" | "CONNECT" | "READV" | "WRITEV" | "CLOSE") {
                assert!(ok, "{name} unexpectedly unsupported");
            }
        }
        let _ = (probe.sqpoll_permitted(), probe.ext_arg(), probe.nodrop());
        let _ = probe.supports_multishot_poll();
        let _ = probe.kernel_release();
    }

    #[test]
    fn unknown_opcode_reads_unsupported() {
        let probe = Probe::detect().expect("probe");
        assert!(!probe.supports_opcode(0xFE));
    }

    #[test]
    fn version_parser() {
        assert_eq!(parse_kernel_version("6.12.4-arch1-1"), (6, 12));
        assert_eq!(parse_kernel_version("5.15.0-generic"), (5, 15));
        assert_eq!(parse_kernel_version("bogus"), (0, 0));
        assert_eq!(parse_kernel_version(""), (0, 0));
        assert_eq!(parse_kernel_version("7"), (0, 0));
    }
}
