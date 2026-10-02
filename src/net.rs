//! Socket setup helpers: listeners with `SO_REUSEPORT` (one per worker for
//! share-nothing accept), nonblocking tuning, keepalive.
//!
//! Extracted from vane-core's `net.rs` (the generic socket-setup half; the
//! proxy-specific pieces stayed in vane).

use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use socket2::{Domain, Protocol, Socket, Type};

/// Creates a nonblocking TCP listener bound to `addr`.
///
/// Sets `SO_REUSEADDR`; on Linux also `SO_REUSEPORT` when `reuse_port` is
/// set so every worker can bind the same address for per-core accept.
///
/// # Errors
/// Bind/listen failure.
pub fn tcp_listener(addr: SocketAddr, reuse_port: bool, backlog: i32) -> io::Result<StdListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    if reuse_port {
        // SAFETY: plain setsockopt with a valid option value.
        set_sock_opt_bool(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEPORT, true)?;
    }
    // IPv6 dual-stack explicit (bind v6 only when v6 addr given).
    if addr.ip().is_ipv6() {
        set_sock_opt_bool(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            true,
        )?;
    }
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    // SAFETY: single ownership transfer of a live listening socket fd.
    Ok(unsafe { StdListener::from_raw_fd(sock.into_raw_fd()) })
}

/// Sets `TCP_NODELAY` (request latency over Nagle).
///
/// # Errors
/// setsockopt failure.
pub fn set_nodelay(fd: RawFd) -> io::Result<()> {
    set_sock_opt_bool(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, true)
}

/// Sets aggressive keepalive so dead peers are noticed.
///
/// # Errors
/// setsockopt failure.
pub fn set_keepalive(fd: RawFd, idle_secs: u32) -> io::Result<()> {
    set_sock_opt_bool(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, true)?;
    // SAFETY: integer options with correct sizes.
    unsafe {
        let v: libc::c_int = idle_secs as libc::c_int;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            std::ptr::addr_of!(v).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let i: libc::c_int = 3;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            std::ptr::addr_of!(i).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let c: libc::c_int = 3;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            std::ptr::addr_of!(c).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

fn set_sock_opt_bool(fd: RawFd, level: libc::c_int, name: libc::c_int, on: bool) -> io::Result<()> {
    let v: libc::c_int = i32::from(on);
    // SAFETY: integer-valued setsockopt with the option's documented size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(v).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Raw stream descriptor owned by a session. Closed on drop.
#[derive(Debug)]
pub struct StreamFd(pub RawFd);

impl StreamFd {
    /// Underlying descriptor.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for StreamFd {
    fn drop(&mut self) {
        // SAFETY: single close of an owned descriptor.
        unsafe { libc::close(self.0) };
    }
}

/// `shutdown(SHUT_WR)` — half-close (finishes streaming responses).
pub fn shutdown_write(fd: RawFd) {
    // SAFETY: live fd; shutdown failure is ignorable.
    unsafe {
        let _ = libc::shutdown(fd, libc::SHUT_WR);
    }
}

#[cfg(test)]
mod net_tests {
    use super::*;

    #[test]
    fn tcp_listener_reuseport_binds() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let l = tcp_listener(addr, true, 64).expect("bind");
        assert!(l.local_addr().is_ok());
    }

    #[test]
    fn set_nodelay_and_keepalive_on_socket() {
        let a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = a.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let fd = client.as_raw_fd();
        set_nodelay(fd).expect("nodelay");
        set_keepalive(fd, 30).expect("keepalive");
    }

    #[test]
    fn set_nodelay_rejects_bad_fd() {
        assert!(set_nodelay(-1).is_err());
    }

    #[test]
    fn stream_fd_closes_on_drop() {
        let (a, b) = socketpair_raw();
        let fd = a;
        let stream = StreamFd(fd);
        assert_eq!(stream.fd(), fd);
        drop(stream);
        // Deterministic liveness check through the peer (fd numbers can be
        // reused by parallel tests, so never probe the raw number): after
        // the drop closed `a`, sends to the peer fail with EPIPE.
        // SAFETY: send on a live descriptor with SIGPIPE suppressed.
        let rc = unsafe { libc::send(b, "x".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPIPE));
        // SAFETY: test-owned peer end.
        unsafe { libc::close(b) };
    }

    fn socketpair_raw() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: plain socketpair with a valid out-array.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (fds[0], fds[1])
    }

    #[test]
    fn shutdown_write_sends_fin() {
        use std::io::Read as _;
        let a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = a.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let mut server = a.incoming().next().expect("stream").expect("accept");
        shutdown_write(client.as_raw_fd());
        // Peer sees EOF.
        let mut buf = [0u8; 1];
        assert_eq!(server.read(&mut buf).expect("read"), 0);
    }
}
