use std::{
    ffi::CString,
    io,
    mem::{self, size_of},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

use elogind_usersv_protocol::{MAX_PACKET_SIZE, ProtocolError, WireMessage};
use thiserror::Error;

#[derive(Debug)]
pub struct SeqPacket {
    fd: OwnedFd,
}

impl SeqPacket {
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let socket = Self::new()?;
        let (address, length) = unix_address(path.as_ref())?;
        // SAFETY: address is initialized for `length`, and fd is a Unix socket.
        cvt(unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        })?;
        Ok(socket)
    }

    pub fn pair() -> io::Result<(Self, Self)> {
        let mut fds = [-1; 2];
        // SAFETY: `fds` points to storage for two descriptors.
        cvt(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        })?;
        // SAFETY: socketpair initialized both descriptors and ownership is unique.
        Ok(unsafe { (Self::from_raw_fd(fds[0]), Self::from_raw_fd(fds[1])) })
    }

    pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        // SAFETY: F_GETFL does not use a variadic argument.
        let flags = cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) })?;
        let flags = if enabled {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: F_SETFL expects one integer argument.
        cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, flags) })?;
        Ok(())
    }

    pub fn set_cloexec(&self, enabled: bool) -> io::Result<()> {
        // SAFETY: F_GETFD does not use a variadic argument.
        let flags = cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFD) })?;
        let flags = if enabled {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        // SAFETY: F_SETFD expects one integer argument.
        cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFD, flags) })?;
        Ok(())
    }

    pub fn set_timeouts(&self, timeout: Duration) -> io::Result<()> {
        let value = libc::timeval {
            tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
            tv_usec: timeout.subsec_micros().into(),
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: value points to a correctly sized timeval.
            cvt(unsafe {
                libc::setsockopt(
                    self.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&value as *const libc::timeval).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            })?;
        }
        Ok(())
    }

    pub fn peer_credentials(&self) -> io::Result<PeerCredentials> {
        // SAFETY: zero is a valid initial representation for ucred.
        let mut credentials: libc::ucred = unsafe { mem::zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the output pointers reference valid writable storage.
        cvt(unsafe {
            libc::getsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        })?;
        if length as usize != size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SO_PEERCRED returned an unexpected size",
            ));
        }
        Ok(PeerCredentials {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
        })
    }

    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is too large",
            ));
        }
        // SAFETY: packet is readable for its complete length.
        let sent = unsafe {
            libc::send(
                self.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial SOCK_SEQPACKET send",
            ));
        }
        Ok(())
    }

    pub fn recv_packet(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        // MSG_TRUNC makes Linux return the original record length when oversized.
        // SAFETY: packet points to writable storage for MAX_PACKET_SIZE bytes.
        let received = unsafe {
            libc::recv(
                self.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "socket closed",
            ));
        }
        if received as usize > MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received oversized packet",
            ));
        }
        packet.truncate(received as usize);
        Ok(packet)
    }

    pub fn send<M: WireMessage>(&self, message: &M) -> Result<(), MessageIoError> {
        self.send_packet(&message.encode()?)?;
        Ok(())
    }

    pub fn recv<M: WireMessage>(&self) -> Result<M, MessageIoError> {
        Ok(M::decode(&self.recv_packet()?)?)
    }

    fn new() -> io::Result<Self> {
        // SAFETY: socket has no pointer arguments.
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was newly returned and ownership is unique.
        Ok(unsafe { Self::from_raw_fd(fd) })
    }

    /// Takes ownership of an existing connected Unix seqpacket descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be valid, uniquely owned, and refer to a connected
    /// `SOCK_SEQPACKET` socket.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            // SAFETY: guaranteed by this function's caller.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }
}

impl AsRawFd for SeqPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for SeqPacket {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

#[derive(Debug)]
pub struct SeqPacketListener {
    fd: OwnedFd,
    path: PathBuf,
}

impl SeqPacketListener {
    pub fn bind(path: impl AsRef<Path>, mode: libc::mode_t, backlog: i32) -> io::Result<Self> {
        let path = path.as_ref();
        let socket = SeqPacket::new()?;
        let (address, length) = unix_address(path)?;
        // SAFETY: address is initialized for `length`, and fd is a Unix socket.
        cvt(unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        })?;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
        // SAFETY: c_path is NUL terminated.
        if unsafe { libc::chmod(c_path.as_ptr(), mode) } < 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        // SAFETY: listen has no pointer arguments.
        if unsafe { libc::listen(socket.as_raw_fd(), backlog) } < 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        let fd = socket.fd;
        Ok(Self {
            fd,
            path: path.to_owned(),
        })
    }

    pub fn accept(&self) -> io::Result<SeqPacket> {
        // SAFETY: null address pointers are allowed when the peer address is unused.
        let fd = unsafe {
            libc::accept4(
                self.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: accept4 returned a new uniquely owned connected descriptor.
        Ok(unsafe { SeqPacket::from_raw_fd(fd) })
    }

    pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        // SAFETY: F_GETFL does not use a variadic argument.
        let flags = cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) })?;
        let flags = if enabled {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: F_SETFL expects one integer argument.
        cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, flags) })?;
        Ok(())
    }
}

impl AsRawFd for SeqPacketListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for SeqPacketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

#[derive(Debug, Error)]
pub enum MessageIoError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

fn unix_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    // SAFETY: zero is the correct initial representation for sockaddr_un.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((address, length as libc::socklen_t))
}

fn cvt(value: libc::c_int) -> io::Result<libc::c_int> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elogind_usersv_protocol::{PamReply, PamRequest};

    #[test]
    fn socket_pair_preserves_packet_boundaries() {
        let (left, right) = SeqPacket::pair().unwrap();
        left.send(&PamReply::Ready).unwrap();
        let reply: PamReply = right.recv().unwrap();
        assert_eq!(reply, PamReply::Ready);
    }

    #[test]
    fn listener_connect_and_peer_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let listener = SeqPacketListener::bind(&path, 0o600, 8).unwrap();
        let client = SeqPacket::connect(&path).unwrap();
        let server = listener.accept().unwrap();
        assert_eq!(server.peer_credentials().unwrap().uid, unsafe {
            libc::geteuid()
        });

        let request = PamRequest::EnsureManagerReady {
            session_id: "c1".into(),
            runtime_dir: "/run/user/1000".into(),
        };
        client.send(&request).unwrap();
        assert_eq!(server.recv::<PamRequest>().unwrap(), request);
    }

    #[test]
    fn rejects_oversized_datagram_without_partial_decode() {
        let (left, right) = SeqPacket::pair().unwrap();
        let bytes = vec![1_u8; MAX_PACKET_SIZE + 1];
        // Bypass the bounded sender to exercise the receiver.
        let sent = unsafe {
            libc::send(
                left.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(sent as usize, bytes.len());
        let error = right.recv_packet().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
