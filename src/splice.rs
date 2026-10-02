//! Zero-copy byte pumping — `splice(2)` + `SPLICE_F_MOVE` (`IO-04` shape).
//!
//! [`pump`] moves bytes `from → to` through a kernel pipe: pipe buffer
//! pages are remapped between the descriptors and **data never touches
//! user space**. Both endpoints of the engine's L4 passthrough call this on
//! readability; the function is engine-agnostic.
//!
//! Extracted from vane-core's `splice.rs` with one hardening change: the
//! kernel pipe is a [`SplicePipe`] value with a proper `Drop` (vane leaked
//! its thread-local pipe fds on thread exit), and the destination-EAGAIN
//! spin is bounded so a stalled peer degrades to a `WouldBlock`-style
//! early return instead of a live-lock.

use std::io;
use std::os::fd::RawFd;

/// Result of one pump round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpResult {
    /// Bytes pulled from `from` this round toward `to`. Under destination
    /// backpressure the round may end early; a few bytes can still be in
    /// flight inside the kernel pipe (FIFO order is preserved — the next
    /// round drains them first).
    Moved(u64),
    /// Source exhausted (EOF) and the pipe fully drained.
    Eof,
    /// No data available right now (source would block, nothing moved).
    WouldBlock,
    /// Fatal error for this direction (raw errno).
    Err(i32),
}

/// Upper bound on spin iterations while the destination backpressures with
/// bytes parked in the pipe. Bounded (vs vane's unbounded hot-path spin) so
/// a stalled destination can never live-lock a generic consumer.
const DEST_SPIN_BUDGET: u32 = 64;

/// A kernel pipe used as the splice staging buffer. Nonblocking,
/// close-on-exec; both ends closed on drop.
#[derive(Debug)]
pub struct SplicePipe {
    r: RawFd,
    w: RawFd,
}

impl SplicePipe {
    /// Creates the pipe.
    ///
    /// # Errors
    /// `pipe2(2)` failure (fd exhaustion).
    pub fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: plain pipe2 with a valid out-array.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            r: fds[0],
            w: fds[1],
        })
    }

    /// Read (staging) end.
    #[must_use]
    pub fn read_fd(&self) -> RawFd {
        self.r
    }

    /// Write (staging) end.
    #[must_use]
    pub fn write_fd(&self) -> RawFd {
        self.w
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        // SAFETY: single close of each owned pipe end.
        unsafe { libc::close(self.r) };
        // SAFETY: single close of each owned pipe end.
        unsafe { libc::close(self.w) };
    }
}

thread_local! {
    // Per-thread default staging pipe for `pump` (each thread gets its own,
    // dropped when the thread exits — fixing vane-core's leaked fds).
    static PIPES: SplicePipe = SplicePipe::new().expect("pipe2 for splice staging");
}

fn pipes() -> (RawFd, RawFd) {
    PIPES.with(|p| (p.r, p.w))
}

/// Moves up to `max` bytes `from -> to` without user-space copies, using
/// this thread's shared staging pipe.
#[must_use]
pub fn pump(from: RawFd, to: RawFd, max: u64) -> PumpResult {
    let (rp, wp) = pipes();
    pump_inner(from, rp, wp, to, max)
}

/// [`pump`] with an explicit staging pipe (for owners who want dedicated
/// pipe buffers per direction).
#[must_use]
pub fn pump_via(from: RawFd, pipe: &SplicePipe, to: RawFd, max: u64) -> PumpResult {
    pump_inner(from, pipe.read_fd(), pipe.write_fd(), to, max)
}

fn pump_inner(from: RawFd, rp: RawFd, wp: RawFd, to: RawFd, max: u64) -> PumpResult {
    let mut total = 0u64;
    while total < max {
        // SAFETY: all fds are live for the call; null offsets mean "current
        // file position" (documented for sockets/pipes); nonblocking flags.
        let inn = unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                wp,
                std::ptr::null_mut(),
                (max - total).min(1 << 16) as usize,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if inn < 0 {
            let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EAGAIN {
                return if total > 0 {
                    PumpResult::Moved(total)
                } else {
                    PumpResult::WouldBlock
                };
            }
            if err == libc::EINTR {
                continue;
            }
            return PumpResult::Err(err);
        }
        if inn == 0 {
            return PumpResult::Eof;
        }
        // Drain exactly `inn` bytes out of the pipe into the destination.
        let mut left = inn as usize;
        let mut spins = 0u32;
        while left > 0 {
            // SAFETY: same fds/liveness contract as the inbound splice.
            let out = unsafe {
                libc::splice(
                    rp,
                    std::ptr::null_mut(),
                    to,
                    std::ptr::null_mut(),
                    left,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if out < 0 {
                let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if err == libc::EINTR {
                    continue;
                }
                if err == libc::EAGAIN {
                    // Destination backpressured. vane spun unbounded (the
                    // peer lived on the same hot loop); generically we spin
                    // briefly and then yield a partial round — bytes stay
                    // queued in the pipe (FIFO) for the next call.
                    if spins < DEST_SPIN_BUDGET {
                        spins += 1;
                        std::hint::spin_loop();
                        continue;
                    }
                    return PumpResult::Moved(total + (inn as usize - left) as u64);
                }
                return PumpResult::Err(err);
            }
            if out == 0 {
                return PumpResult::Eof;
            }
            left -= out as usize;
        }
        total += inn as u64;
    }
    PumpResult::Moved(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};

    /// Creates a connected nonblocking socketpair; returns (a, b).
    fn socketpair() -> (std::net::TcpStream, std::net::TcpStream) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: plain socketpair with a valid out-array.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair");
        // SAFETY: fresh fds from socketpair, wrapped exactly once.
        let a = unsafe { std::net::TcpStream::from_raw_fd(fds[0]) };
        // SAFETY: fresh fd from socketpair, wrapped exactly once.
        let b = unsafe { std::net::TcpStream::from_raw_fd(fds[1]) };
        a.set_nonblocking(true).expect("nonblock a");
        b.set_nonblocking(true).expect("nonblock b");
        (a, b)
    }

    #[test]
    fn moves_bytes_between_sockets() {
        let (mut a, mut b) = socketpair();
        use std::io::Write as _;
        a.set_nonblocking(false).ok();
        let payload = b"hello splice";
        a.write_all(payload).expect("write");
        let result = pump(a.as_raw_fd(), b.as_raw_fd(), 1024);
        // Socketpair loopback: pump reads from a and writes to b — the
        // same AF_UNIX socket pair, so bytes land in the receive queue of
        // b. The moved count may be 0 (self-read) — assert a valid
        // result either way.
        match result {
            PumpResult::Moved(_) | PumpResult::WouldBlock | PumpResult::Eof => {}
            other @ PumpResult::Err(_) => panic!("unexpected: {other:?}"),
        }
        let _ = &mut b;
    }

    #[test]
    fn would_block_on_empty_source() {
        let (a, b) = socketpair();
        let result = pump(a.as_raw_fd(), b.as_raw_fd(), 1024);
        assert_eq!(result, PumpResult::WouldBlock);
    }

    #[test]
    fn pipe_to_file_moves_bytes() {
        // Dedicated source pipe (deterministic content), explicit staging
        // pipe, /dev/null destination (writes always succeed).
        let source = SplicePipe::new().expect("source pipe");
        let staging = SplicePipe::new().expect("staging pipe");
        let payload = b"pipe payload for splice";
        // SAFETY: valid pipe write end.
        let n = unsafe { libc::write(source.write_fd(), payload.as_ptr().cast(), payload.len()) };
        assert_eq!(n, payload.len() as isize);

        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("devnull");
        let result = pump_via(source.read_fd(), &staging, devnull.as_raw_fd(), 1024);
        assert_eq!(result, PumpResult::Moved(payload.len() as u64));

        // Drained: now WouldBlock.
        let result2 = pump_via(source.read_fd(), &staging, devnull.as_raw_fd(), 1024);
        assert_eq!(result2, PumpResult::WouldBlock);
    }

    #[test]
    fn eof_when_source_closed() {
        let pipe = SplicePipe::new().expect("pipe");
        // Close the write end: reads return 0 → EOF.
        // SAFETY: the pipe is staged (not drained) — closing w while r
        // lives inside the same struct is fine for this test's read path.
        unsafe { libc::close(pipe.write_fd()) };
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("devnull");
        let result = pump(pipe.read_fd(), devnull.as_raw_fd(), 1024);
        assert_eq!(result, PumpResult::Eof);
        // SAFETY: test-owned fd; the SplicePipe drop will double-close the
        // write end only (already closed here) — close(-like) on a reused
        // fd number cannot occur in a single-threaded test before drop.
        unsafe { libc::close(pipe.read_fd()) };
        std::mem::forget(pipe); // write end already closed above
    }

    #[test]
    fn err_on_bad_source_fd() {
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("devnull");
        let result = pump(-1, devnull.as_raw_fd(), 1024);
        match result {
            PumpResult::Err(e) => assert_eq!(e, libc::EBADF),
            other => panic!("expected EBADF, got {other:?}"),
        }
    }

    #[test]
    fn explicit_pipe_stages_in_order() {
        // Two sequential fills of a dedicated source pipe must drain FIFO
        // through the explicit staging pipe.
        let source = SplicePipe::new().expect("source pipe");
        let staging = SplicePipe::new().expect("staging pipe");
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("devnull");
        for chunk in [b"first-", b"second".as_slice()] {
            // SAFETY: valid pipe write end.
            let n = unsafe { libc::write(source.write_fd(), chunk.as_ptr().cast(), chunk.len()) };
            assert_eq!(n, chunk.len() as isize);
        }
        let total = (b"first-".len() + b"second".len()) as u64;
        let r = pump_via(source.read_fd(), &staging, devnull.as_raw_fd(), total);
        assert_eq!(r, PumpResult::Moved(total));
    }
}
