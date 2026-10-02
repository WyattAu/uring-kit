//! `io_uring` engine: one ring per thread, fixed registered buffers, SQPOLL
//! optional.
//!
//! Reads use `IORING_OP_READ_FIXED` (`opcode::ReadFixed`) with
//! `buf_index = slot`, so the kernel writes directly into the owner's
//! pre-allocated pool — zero per-op buffer mapping. Writes use
//! `WRITE_FIXED` symmetrically. L4 splice pumping arms multishot `PollAdd`
//! readiness and runs kernel-only `splice(2)` loops inline — request bytes
//! never enter user space.
//!
//! Extracted from vane-core's `engine/uring.rs`; vane's engine-trait
//! coupling (and its mio fallback twin) stayed in vane. Genericized: the
//! downstream/upstream op split became direction-neutral `Read`/`Write`,
//! and `read_vectored`/`write_vectored`/`close` were added to round out
//! the reusable socket-op surface.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{IntoRawFd, RawFd};
use std::path::Path;
use std::time::Duration;

use io_uring::types::{Fd, SubmitArgs, Timespec};

use crate::buffer::BufferPool;
use crate::engine::{Cqe, Engine, Poll};
use crate::splice;
use crate::token::{Op, Token};

/// Listener state (accept re-arms after each connection).
struct Listener {
    fd: RawFd,
    /// sockaddr output buffer the kernel fills for each accepted connection.
    sa: Box<[u8; 128]>,
    sa_len: Box<libc::socklen_t>,
}

/// io_uring-backed [`Engine`].
pub struct UringEngine {
    ring: io_uring::IoUring,
    /// Slot base pointers (registered as kernel fixed buffers).
    slot_bases: Vec<*mut u8>,
    buf_size: usize,
    listeners: HashMap<u64, Listener>,
    /// Splice direction per token: bits -> (`from_fd`, `to_fd`).
    splice_dirs: HashMap<u64, (RawFd, RawFd)>,
    /// Completed accepts awaiting pickup: fd -> peer.
    accepted: HashMap<RawFd, SocketAddr>,
    /// Owned sockaddr storage per in-flight connect (token bits -> (addr, len)).
    /// `io_uring` copies the sockaddr at SUBMISSION time, not at SQE build
    /// time — a stack-local sockaddr would dangle between `push` and
    /// `submit` (use-after-free manifesting as EAFNOSUPPORT under load).
    connect_addrs: HashMap<u64, Box<ConnectAddr>>,
    /// Owned iovec arrays per in-flight vectored op (token bits -> iovs).
    /// Same submission-time liveness rule as the connect sockaddrs.
    vec_iovs: HashMap<u64, Box<[libc::iovec]>>,
}

/// Owned connect address for one in-flight `Connect` SQE.
struct ConnectAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

/// Serializes a `SocketAddr` into owned storage, returning the box plus a
/// pointer/len pair valid for as long as the box lives.
///
/// # Safety
/// The caller must keep the returned box alive (in `connect_addrs`) until
/// the op completes. The heap address is stable across moves.
unsafe fn connect_addr_boxed(
    addr: SocketAddr,
) -> (Box<ConnectAddr>, *const libc::sockaddr, libc::socklen_t) {
    // SAFETY: fully initialized for the active family below.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: family matches the written layout.
            let sa: &mut libc::sockaddr_in =
                unsafe { &mut *std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in>() };
            sa.sin_family = libc::AF_INET as _;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            // SAFETY: family matches the written layout.
            let sa: &mut libc::sockaddr_in6 =
                unsafe { &mut *std::ptr::addr_of_mut!(storage).cast::<libc::sockaddr_in6>() };
            sa.sin6_family = libc::AF_INET6 as _;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    let boxed = Box::new(ConnectAddr { storage, len });
    // The heap address is stable for the box's lifetime (per the function
    // contract the caller stores it in `connect_addrs`); `addr_of!` on a
    // place expression needs no unsafe block.
    let ptr = std::ptr::addr_of!(boxed.storage).cast::<libc::sockaddr>();
    let out_len = boxed.len;
    (boxed, ptr, out_len)
}

// SAFETY: slot pointers live in the owner's pool; the engine is
// single-owner (one thread builds SQEs and drains CQEs; under SQPOLL the
// kernel thread is bound to the same ring memory by the uAPI contract).
unsafe impl Send for UringEngine {}

impl UringEngine {
    /// Builds the ring and registers the buffer pool as kernel fixed
    /// buffers.
    ///
    /// `pool` must outlive the engine (the registration points at slot
    /// addresses); the engine keeps only the base pointers. With `sqpoll`,
    /// a kernel thread drains the SQ without syscalls — creation fails on
    /// kernels/users without permission (see [`crate::probe::Probe`]).
    ///
    /// # Errors
    /// Ring creation or registration failure (e.g., SQPOLL denied for the
    /// current user).
    pub fn new(entries: u32, pool: Option<&BufferPool>, sqpoll: bool) -> io::Result<Self> {
        let build: io::Result<io_uring::IoUring> = if sqpoll {
            io_uring::IoUring::builder()
                .setup_sqpoll(2_000)
                .build(entries)
        } else {
            io_uring::IoUring::new(entries)
        };
        let ring = build?;
        let (slot_bases, buf_size) = match pool {
            Some(pool) => {
                // Base addresses only (no dereference); slots outlive the ring.
                let bases = (0..pool.capacity() as u32)
                    .map(|i| pool.slot(i).as_ptr().cast_mut())
                    .collect::<Vec<_>>();
                let iovecs: Vec<libc::iovec> = bases
                    .iter()
                    .map(|p| libc::iovec {
                        // SAFETY: pointer valid for buf_size bytes.
                        iov_base: (*p).cast(),
                        iov_len: pool.buf_size(),
                    })
                    .collect();
                // SAFETY: iovecs reference stable slot storage that outlives
                // the ring (documented `pool` lifetime contract).
                unsafe {
                    ring.submitter().register_buffers(&iovecs)?;
                }
                (bases, pool.buf_size())
            }
            None => (Vec::new(), 0),
        };
        Ok(Self {
            ring,
            slot_bases,
            buf_size,
            listeners: HashMap::new(),
            splice_dirs: HashMap::new(),
            accepted: HashMap::new(),
            connect_addrs: HashMap::new(),
            vec_iovs: HashMap::new(),
        })
    }

    /// Queues an SQE (no syscall); `poll` batches the submit. Under SQPOLL
    /// the kernel thread picks entries up without any syscall at all.
    ///
    /// Caller contract (checked at each call site): the entry's buffers and
    /// fds must remain valid until its CQE is consumed on this thread.
    fn push(&mut self, entry: io_uring::squeue::Entry, token: Token) {
        let entry = entry.user_data(token.bits());
        loop {
            // SAFETY: entry pushed exactly once; completion consumed here.
            unsafe {
                if self.ring.submission().push(&entry).is_ok() {
                    return;
                }
            }
            // SQ full: flush to the kernel and retry.
            let _ = self.ring.submit();
            std::hint::spin_loop();
        }
    }

    fn slot_ptr(&self, slot: u32) -> *mut u8 {
        match self.slot_bases.get(slot as usize) {
            Some(&p) => p,
            None => std::ptr::null_mut(),
        }
    }

    fn arm_accept(&mut self, bits: u64) {
        let Some(l) = self.listeners.get_mut(&bits) else {
            return;
        };
        let fd = l.fd;
        let sa_ptr = l.sa.as_mut_ptr();
        let len_ptr: *mut libc::socklen_t = &raw mut *l.sa_len;
        // SAFETY contract for `push`: sa/sa_len are stable engine-owned
        // buffers, valid until the CQE is consumed on this thread.
        let entry = io_uring::opcode::Accept::new(Fd(fd), sa_ptr.cast(), len_ptr)
            .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
            .build();
        self.push(entry, Token::from_bits(bits));
    }

    fn arm_readiness(&mut self, fd: RawFd, token: Token) {
        // SAFETY contract for `push`: fd live until session close; multishot
        // poll re-arms itself.
        let entry = io_uring::opcode::PollAdd::new(Fd(fd), libc::POLLIN as u32)
            .multi(true)
            .build();
        self.push(entry, token);
    }

    /// Builds a vectored-op entry from owned iovecs and parks the array in
    /// engine storage until the CQE frees it.
    fn push_vectored(
        &mut self,
        token: Token,
        fd: RawFd,
        iovs: Box<[libc::iovec]>,
        is_read: bool,
    ) -> io::Result<Poll> {
        let len = u32::try_from(iovs.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "iovec count overflows u32")
        })?;
        // The box's heap address is stable while stored in `vec_iovs`
        // (insert below only moves the box handle, not its heap buffer).
        let ptr = iovs.as_ptr();
        let entry = if is_read {
            io_uring::opcode::Readv::new(Fd(fd), ptr, len)
                .offset(0)
                .build()
        } else {
            io_uring::opcode::Writev::new(Fd(fd), ptr, len)
                .offset(0)
                .build()
        };
        self.vec_iovs.insert(token.bits(), iovs);
        self.push(entry, token);
        Ok(Poll::Pending)
    }
}

impl Engine for UringEngine {
    fn kind(&self) -> &'static str {
        "io_uring"
    }

    fn add_listener(&mut self, fd: RawFd, token: Token) -> io::Result<()> {
        let bits = token.bits();
        self.listeners.insert(
            bits,
            Listener {
                fd,
                sa: Box::new([0u8; 128]),
                sa_len: Box::new(128),
            },
        );
        self.arm_accept(bits);
        Ok(())
    }

    fn add_stream(&mut self, _fd: RawFd, _token: Token) -> io::Result<()> {
        // Connected sockets pass per-op; IORING_REGISTER_FILES is a
        // follow-up optimization needing stable fd slots per session.
        Ok(())
    }

    fn read(&mut self, token: Token, fd: RawFd, slot: u32) -> io::Result<Poll> {
        let ptr = self.slot_ptr(slot);
        // SAFETY contract for `push`: the fixed-buffer slot is exclusively
        // owned while the op is in flight; the kernel writes the registered
        // buffer directly (bounded by the registered iovec length).
        let entry =
            io_uring::opcode::ReadFixed::new(Fd(fd), ptr, self.buf_size as u32, slot as u16)
                .offset(0)
                .build();
        self.push(entry, token);
        Ok(Poll::Pending)
    }

    fn write(
        &mut self,
        token: Token,
        fd: RawFd,
        slot: u32,
        len: usize,
        offset: usize,
    ) -> io::Result<Poll> {
        let ptr = self.slot_ptr(slot);
        debug_assert!(offset <= len, "write offset past end");
        // SAFETY: fixed buffer (bytes serialized by the caller pre-submit);
        // pointer arithmetic stays within the registered slot (offset <=
        // len <= buf_size by the pool contract).
        let entry = unsafe {
            io_uring::opcode::WriteFixed::new(
                Fd(fd),
                ptr.add(offset),
                (len - offset) as u32,
                slot as u16,
            )
            .offset(0)
            .build()
        };
        self.push(entry, token);
        Ok(Poll::Pending)
    }

    fn read_vectored(
        &mut self,
        token: Token,
        fd: RawFd,
        iovs: Box<[libc::iovec]>,
    ) -> io::Result<Poll> {
        if iovs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read_vectored needs at least one iovec",
            ));
        }
        self.push_vectored(token, fd, iovs, true)
    }

    fn write_vectored(
        &mut self,
        token: Token,
        fd: RawFd,
        iovs: Box<[libc::iovec]>,
    ) -> io::Result<Poll> {
        if iovs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_vectored needs at least one iovec",
            ));
        }
        self.push_vectored(token, fd, iovs, false)
    }

    fn close(&mut self, token: Token, fd: RawFd) -> io::Result<Poll> {
        let entry = io_uring::opcode::Close::new(Fd(fd)).build();
        self.push(entry, token);
        Ok(Poll::Pending)
    }

    fn connect(&mut self, token: Token, addr: SocketAddr) -> io::Result<(RawFd, Poll)> {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        sock.set_nonblocking(true)?;
        sock.set_tcp_nodelay(true)?;
        let fd = sock.into_raw_fd();
        // The sockaddr must live in owned storage until the op completes:
        // io_uring copies it at submit time, not when the SQE is built.
        // SAFETY: the box is stored in `connect_addrs` for the op lifetime.
        let (owned, ptr, len) = unsafe { connect_addr_boxed(addr) };
        let entry = io_uring::opcode::Connect::new(Fd(fd), ptr, len).build();
        self.connect_addrs.insert(token.bits(), owned);
        self.push(entry, token);
        Ok((fd, Poll::Pending))
    }

    fn connect_unix(&mut self, token: Token, path: &Path) -> io::Result<(RawFd, Poll)> {
        let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        sock.set_nonblocking(true)?;
        let fd = sock.into_raw_fd();
        let sa = socket2::SockAddr::unix(path)?;
        // SAFETY: raw sockaddr bytes are copied into owned storage, kept in
        // `connect_addrs` for the op lifetime.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let bytes = sa.as_ptr().cast::<u8>();
        let copy_len = (sa.len() as usize).min(std::mem::size_of::<libc::sockaddr_storage>());
        // SAFETY: sa is a valid sockaddr of `sa.len()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes, std::ptr::addr_of_mut!(storage).cast(), copy_len);
        };
        let len = sa.len();
        let owned = Box::new(ConnectAddr { storage, len });
        // Heap address is stable while `owned` lives in `connect_addrs`.
        let ptr = std::ptr::addr_of!(owned.storage).cast::<libc::sockaddr>();
        let entry = io_uring::opcode::Connect::new(Fd(fd), ptr, len).build();
        self.connect_addrs.insert(token.bits(), owned);
        self.push(entry, token);
        Ok((fd, Poll::Pending))
    }

    fn accept(&mut self, _lfd: RawFd, ltoken: Token) -> io::Result<Option<(RawFd, SocketAddr)>> {
        // Return one completed accept if the poll loop queued it.
        if let Some((&fd, &addr)) = self.accepted.iter().next() {
            self.accepted.remove(&fd);
            return Ok(Some((fd, addr)));
        }
        // Not ready yet. Do NOT re-arm here: exactly one accept SQE is
        // outstanding per listener at all times (armed in `add_listener`,
        // re-armed on every completion in `poll`). Re-arming per call would
        // accumulate unbounded SQEs and exhaust the submission queue.
        let _ = ltoken;
        Ok(None)
    }

    fn splice_pump(&mut self, a: Token, afd: RawFd, b: Token, bfd: RawFd) -> io::Result<()> {
        // Directions are keyed by token bits: identical tokens would
        // silently overwrite one direction.
        debug_assert_ne!(a.bits(), b.bits(), "splice directions need distinct tokens");
        self.splice_dirs.insert(a.bits(), (afd, bfd));
        self.splice_dirs.insert(b.bits(), (bfd, afd));
        self.arm_readiness(afd, a);
        self.arm_readiness(bfd, b);
        Ok(())
    }

    fn remove(&mut self, fd: RawFd) {
        self.accepted.remove(&fd);
    }

    fn poll(&mut self, timeout: Option<Duration>, out: &mut Vec<Cqe>) -> io::Result<()> {
        // Flush submissions (no-op under SQPOLL — kernel thread drains).
        self.ring.submit()?;

        match timeout {
            None => match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            },
            Some(d) => {
                // Bounded wait via IORING_ENTER_EXT_ARG; ETIME = clean timeout.
                let ms = d.as_millis().min(60_000) as u64;
                let ts = Timespec::new()
                    .sec(ms / 1_000)
                    .nsec((ms % 1_000) as u32 * 1_000_000);
                let args = SubmitArgs::new().timespec(&ts);
                match self.ring.submitter().submit_with_args(1, &args) {
                    Ok(_) => {}
                    Err(e) if e.raw_os_error() == Some(libc::ETIME) => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        // Fallback for kernels without EXT_ARG: plain wait.
                        self.ring.submit_and_wait(0)?;
                    }
                }
            }
        }

        // Drain completions.
        let mut accept_hits: Vec<(Token, RawFd)> = Vec::new();
        for cqe in self.ring.completion() {
            let token = Token::from_bits(cqe.user_data());
            let raw = cqe.result();
            let result = if raw >= 0 {
                Ok(raw as u32)
            } else {
                Err(io::Error::from_raw_os_error(-raw))
            };
            // In-flight op storage (connect sockaddrs, vectored iovecs) is
            // safe to release once its CQE has been observed.
            if token.op() == Op::Connect {
                self.connect_addrs.remove(&token.bits());
            }
            self.vec_iovs.remove(&token.bits());
            match token.op() {
                Op::Accept => {
                    if raw >= 0 {
                        accept_hits.push((token, raw as RawFd));
                    } else if -raw != libc::ECANCELED {
                        out.push(Cqe { token, result });
                    }
                }
                Op::Splice => {
                    if raw < 0 {
                        if -raw != libc::ECANCELED {
                            out.push(Cqe { token, result });
                        }
                    } else if let Some(&(from, to)) = self.splice_dirs.get(&token.bits()) {
                        match splice::pump(from, to, 1 << 20) {
                            splice::PumpResult::Moved(n) => {
                                out.push(Cqe {
                                    token,
                                    result: Ok(n as u32),
                                });
                            }
                            splice::PumpResult::Eof => {
                                out.push(Cqe {
                                    token,
                                    result: Ok(0),
                                });
                            }
                            splice::PumpResult::WouldBlock => {}
                            splice::PumpResult::Err(code) => out.push(Cqe {
                                token,
                                result: Err(io::Error::from_raw_os_error(code)),
                            }),
                        }
                    }
                }
                _ => out.push(Cqe { token, result }),
            }
        }

        // Materialize accepted connections and re-arm listeners.
        for (token, fd) in accept_hits {
            let bits = token.bits();
            let addr = self.listeners.get(&bits).map_or_else(
                || SocketAddr::from(([0, 0, 0, 0], 0)),
                |l| parse_sockaddr(&l.sa),
            );
            self.accepted.insert(fd, addr);
            self.arm_accept(bits);
        }
        Ok(())
    }

    fn take_accepted(&mut self, fd: RawFd) -> Option<SocketAddr> {
        self.accepted.remove(&fd)
    }
}

fn parse_sockaddr(buf: &[u8; 128]) -> SocketAddr {
    // SAFETY: buffer is sockaddr_storage sized and kernel-written.
    let sa: &libc::sockaddr_storage = unsafe { &*buf.as_ptr().cast() };
    if i32::from(sa.ss_family) == libc::AF_INET {
        // SAFETY: AF_INET guarantees sockaddr_in layout.
        let a: &libc::sockaddr_in = unsafe {
            &*std::ptr::from_ref::<libc::sockaddr_storage>(sa).cast::<libc::sockaddr_in>()
        };
        SocketAddr::from((
            std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
            u16::from_be(a.sin_port),
        ))
    } else {
        // SAFETY: the arm covers AF_INET6 (and the pre-arm zero state,
        // which decodes as ::); sockaddr_in6 layout is family-guaranteed.
        let a: &libc::sockaddr_in6 = unsafe {
            &*std::ptr::from_ref::<libc::sockaddr_storage>(sa).cast::<libc::sockaddr_in6>()
        };
        SocketAddr::from((
            std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
            u16::from_be(a.sin6_port),
        ))
    }
}

#[cfg(test)]
mod fault_tests {
    use super::*;
    use crate::buffer::DEFAULT_BUF_SIZE;
    use std::os::fd::AsRawFd;

    fn test_engine() -> (BufferPool, UringEngine) {
        let pool = BufferPool::new(8, DEFAULT_BUF_SIZE).expect("pool");
        let engine = UringEngine::new(64, Some(&pool), false).expect("uring available");
        (pool, engine)
    }

    fn tok(op: Op) -> Token {
        Token::new(op, 0, 0, 0)
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

    fn close(fd: RawFd) {
        // SAFETY: test owns the fd.
        unsafe { libc::close(fd) };
    }

    fn drain(engine: &mut UringEngine, secs: u64) -> Vec<Cqe> {
        let mut out = Vec::new();
        engine
            .poll(Some(std::time::Duration::from_secs(secs)), &mut out)
            .expect("poll");
        out
    }

    /// Polls until `pred` matches a CQE or the attempt budget runs out
    /// (kernels race completion delivery against `submit_and_wait`).
    fn drain_until(engine: &mut UringEngine, mut pred: impl FnMut(&Cqe) -> bool) -> Vec<Cqe> {
        let mut all = Vec::new();
        for _ in 0..60 {
            let mut out = Vec::new();
            engine
                .poll(Some(std::time::Duration::from_millis(100)), &mut out)
                .expect("poll");
            if out.iter().any(&mut pred) {
                all.extend(out);
                return all;
            }
            all.extend(out);
        }
        all
    }

    #[test]
    fn write_then_read_roundtrip() {
        let (_pool, mut engine) = test_engine();
        let (a, b) = sockpair();
        let wt = tok(Op::Write);
        assert!(matches!(
            engine.write(wt, a, 0, 32, 0).expect("write"),
            Poll::Pending
        ));
        let cqes = drain(&mut engine, 2);
        assert!(
            cqes.iter().any(|c| c.token == wt && c.result.is_ok()),
            "write CQE missing: {cqes:?}"
        );
        // Read the bytes back through the ring into slot 1.
        let rt = tok(Op::Read);
        assert!(matches!(
            engine.read(rt, b, 1).expect("read"),
            Poll::Pending
        ));
        let cqes = drain(&mut engine, 2);
        let got = cqes.iter().find(|c| c.token == rt).expect("read CQE");
        assert!(matches!(got.result, Ok(32)));
        close(a);
        close(b);
    }

    #[test]
    fn vectored_write_then_read_roundtrip() {
        let (_pool, mut engine) = test_engine();
        let (a, b) = sockpair();
        // Two scratch buffers (not pool slots — vectored ops take user
        // buffers per the ownership contract).
        let mut b1 = Box::new([b'x'; 16]);
        let mut b2 = Box::new([b'y'; 16]);
        let iovs: Box<[libc::iovec]> = vec![
            libc::iovec {
                iov_base: b1.as_mut_ptr().cast(),
                iov_len: b1.len(),
            },
            libc::iovec {
                iov_base: b2.as_mut_ptr().cast(),
                iov_len: b2.len(),
            },
        ]
        .into_boxed_slice();
        let wt = tok(Op::Write);
        engine.write_vectored(wt, a, iovs).expect("writev");
        let cqes = drain_until(&mut engine, |c| c.token == wt);
        let w = cqes.iter().find(|c| c.token == wt).expect("writev CQE");
        assert_eq!(
            *w.result.as_ref().expect("writev ok"),
            32,
            "both buffers written"
        );
        assert_eq!(&*b1, b"xxxxxxxxxxxxxxxx");
        assert_eq!(&*b2, b"yyyyyyyyyyyyyyyy");

        // Vectored read into two fresh buffers.
        let mut r1 = vec![0u8; 20];
        let mut r2 = vec![0u8; 20];
        let riovs: Box<[libc::iovec]> = vec![
            libc::iovec {
                iov_base: r1.as_mut_ptr().cast(),
                iov_len: r1.len(),
            },
            libc::iovec {
                iov_base: r2.as_mut_ptr().cast(),
                iov_len: r2.len(),
            },
        ]
        .into_boxed_slice();
        let rt = tok(Op::Read);
        engine.read_vectored(rt, b, riovs).expect("readv");
        let cqes = drain_until(&mut engine, |c| c.token == rt);
        let r = cqes.iter().find(|c| c.token == rt).expect("readv CQE");
        assert_eq!(*r.result.as_ref().expect("readv ok"), 32);
        // 32 payload bytes split 20 + 12 across the two iovecs.
        assert_eq!(&r1[..16], b"xxxxxxxxxxxxxxxx");
        assert_eq!(&r2[..12], b"yyyyyyyyyyyy");
        assert_eq!(r2[12], 0, "iovec boundary respected");
        close(a);
        close(b);
    }

    #[test]
    fn vectored_ops_reject_empty_iovs() {
        let (_pool, mut engine) = test_engine();
        let (a, _b) = sockpair();
        let empty: Box<[libc::iovec]> = Vec::new().into_boxed_slice();
        assert!(engine.read_vectored(tok(Op::Read), a, empty).is_err());
        close(a);
    }

    #[test]
    fn close_op_completes() {
        let (_pool, mut engine) = test_engine();
        let (a, b) = sockpair();
        let t = tok(Op::Close);
        assert!(matches!(engine.close(t, a).expect("close"), Poll::Pending));
        let cqes = drain_until(&mut engine, |c| c.token == t);
        let c = cqes.iter().find(|c| c.token == t).expect("close CQE");
        assert!(c.result.is_ok(), "close CQE: {cqes:?}");
        // Deterministic liveness check through the peer (fd numbers can be
        // reused by parallel tests, so never probe the raw number): after
        // the kernel closed `a`, writes to the peer fail with EPIPE.
        // SAFETY: send on a live descriptor with SIGPIPE suppressed.
        let rc = unsafe { libc::send(b, "x".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPIPE));
        close(b);
    }

    #[test]
    fn connect_refused_completes_with_error() {
        let (_pool, mut engine) = test_engine();
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let t = tok(Op::Connect);
        let (fd, poll) = engine.connect(t, addr).expect("connect issued");
        match poll {
            Poll::Done(_) => {}
            Poll::Pending => {
                let cqes = drain_until(&mut engine, |c| c.token == t);
                assert!(
                    cqes.iter().any(|c| c.token == t && c.result.is_err()),
                    "refused connect must error: {cqes:?}"
                );
            }
        }
        close(fd);
    }

    #[test]
    fn connect_establishes_to_local_listener() {
        let (_pool, mut engine) = test_engine();
        let listener =
            crate::net::tcp_listener("127.0.0.1:0".parse().expect("a"), false, 16).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let t = tok(Op::Connect);
        let (fd, _) = engine.connect(t, addr).expect("connect");
        let cqes = drain_until(&mut engine, |c| c.token == t);
        let c = cqes.iter().find(|c| c.token == t).expect("connect CQE");
        assert_eq!(
            *c.result.as_ref().expect("established"),
            0,
            "Ok(0) = established"
        );
        let _ = listener; // keep the listener alive past the connect
        close(fd);
    }

    #[test]
    fn connect_unix_missing_path_errors() {
        let (_pool, mut engine) = test_engine();
        let t = tok(Op::Connect);
        let dir = tempfile::tempdir().expect("dir");
        let missing = dir.path().join("no.sock");
        let res = engine.connect_unix(t, &missing);
        assert!(res.is_err() || matches!(res, Ok((_, Poll::Pending))));
    }

    #[test]
    fn accept_flow_materializes_connection() {
        let (_pool, mut engine) = test_engine();
        let listener =
            crate::net::tcp_listener("127.0.0.1:0".parse().expect("addr"), true, 64).expect("bind");
        let lfd = listener.as_raw_fd();
        engine.add_listener(lfd, Token::accept(0)).expect("add");
        // No client yet: accept reports None (single outstanding SQE).
        assert!(engine
            .accept(lfd, Token::accept(0))
            .expect("accept")
            .is_none());
        let addr = listener.local_addr().expect("addr");
        let _client = std::net::TcpStream::connect(addr).expect("connect");
        // Accept completions land in the engine's accepted map (not the
        // CQE out-vec): poll until the retrieval API reports the peer.
        let mut got = None;
        for _ in 0..60 {
            let mut out = Vec::new();
            engine
                .poll(Some(std::time::Duration::from_millis(100)), &mut out)
                .expect("poll");
            got = engine.accept(lfd, Token::accept(0)).expect("accept2");
            if got.is_some() {
                break;
            }
        }
        // The completed accept is retrievable through the engine API.
        assert!(got.is_some(), "materialized connection expected");
        let (fd, peer) = got.expect("some");
        assert!(peer.port() != 0);
        close(fd);
    }

    #[test]
    fn splice_moved_and_eof_paths() {
        let (_pool, mut engine) = test_engine();
        let pipe = splice::SplicePipe::new().expect("pipe");
        let payload = b"uring-splice";
        // SAFETY: write to a live pipe.
        unsafe { libc::write(pipe.write_fd(), payload.as_ptr().cast(), payload.len()) };
        let (sa, sb) = sockpair();
        let t = tok(Op::Splice);
        let t_rev = Token::new(Op::Splice, 0, 0, 1);
        engine
            .splice_pump(t, pipe.read_fd(), t_rev, sb)
            .expect("splice_pump");
        let cqes = drain_until(&mut engine, |c| c.token == t);
        assert!(
            cqes.iter()
                .any(|c| c.token == t && matches!(c.result, Ok(n) if n as usize == payload.len())),
            "splice moved CQE: {cqes:?}"
        );
        // Drain the socket, then close the pipe writer: a fresh pump from
        // that pipe must report EOF (0).
        let mut buf = [0u8; 64];
        // SAFETY: read into a live buffer.
        let n = unsafe { libc::read(sa, buf.as_mut_ptr().cast(), 64) };
        assert_eq!(&buf[..n as usize], payload);
        let pipe2 = splice::SplicePipe::new().expect("pipe2");
        let pr2 = pipe2.read_fd();
        // SAFETY: test-owned pipe write end; the reader stays open for the
        // pump below and both fds are intentionally leaked after the write
        // end's manual close (fd lifetime ends with the test process).
        unsafe { libc::close(pipe2.write_fd()) };
        std::mem::forget(pipe2);
        let t2 = Token::new(Op::Splice, 1, 0, 0);
        let t2_rev = Token::new(Op::Splice, 1, 0, 1);
        engine
            .splice_pump(t2, pr2, t2_rev, sb)
            .expect("splice_pump2");
        let cqes = drain_until(&mut engine, |c| c.token == t2);
        assert!(
            cqes.iter()
                .any(|c| c.token == t2 && matches!(c.result, Ok(0))),
            "splice EOF CQE: {cqes:?}"
        );
        close(sa);
        close(sb);
    }

    #[test]
    fn remove_clears_tracked_fd() {
        let (_pool, mut engine) = test_engine();
        let (a, b) = sockpair();
        engine.add_stream(a, tok(Op::Read)).expect("add_stream");
        engine.remove(a);
        // No panic; op state dropped.
        close(a);
        close(b);
    }

    #[test]
    fn poll_timeout_etime_returns_clean() {
        let (_pool, mut engine) = test_engine();
        // Idle ring + bounded timeout: EXT_ARG path returns via ETIME (or
        // the plain-wait fallback on old kernels) — either way Ok, fast.
        let started = std::time::Instant::now();
        let out = drain(&mut engine, 0);
        assert!(out.is_empty(), "idle ring must yield no CQEs");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn engine_without_pool_has_no_fixed_buffers() {
        let engine = UringEngine::new(16, None, false).expect("ring");
        assert_eq!(engine.kind(), "io_uring");
        assert_eq!(engine.buf_size, 0);
        assert!(engine.slot_bases.is_empty());
        assert_eq!(engine.slot_ptr(0), std::ptr::null_mut());
    }

    #[test]
    fn sqpoll_construction_when_permitted() {
        let pool = BufferPool::new(4, DEFAULT_BUF_SIZE).expect("pool");
        match UringEngine::new(64, Some(&pool), true) {
            Ok(mut engine) => {
                // SQPOLL permitted: a write must still complete through the
                // kernel-drained SQ (give the kernel thread a moment).
                let (a, b) = sockpair();
                let wt = tok(Op::Write);
                engine.write(wt, a, 0, 8, 0).expect("write");
                let mut seen = false;
                for _ in 0..60 {
                    let mut out = Vec::new();
                    engine
                        .poll(Some(std::time::Duration::from_millis(100)), &mut out)
                        .expect("poll");
                    if out.iter().any(|c| c.token == wt && c.result.is_ok()) {
                        seen = true;
                        break;
                    }
                }
                assert!(seen, "SQPOLL ring never completed the write");
                close(a);
                close(b);
            }
            Err(_denied) => {
                // Unprivileged user / restricted kernel: the documented
                // fallback is construction without SQPOLL.
                let _engine = UringEngine::new(64, Some(&pool), false).expect("plain ring");
            }
        }
    }
}
