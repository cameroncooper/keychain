//! Kernel-supplied Unix-socket identity. This authenticates a UID, not an app.
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn credentials(stream: &UnixStream) -> io::Result<Credentials> {
    let mut value = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: initialized ucred output and length, both live for this call;
    // SO_PEERCRED is queried on an owned connected Unix socket.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut value as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<libc::ucred>() || value.pid <= 0 {
        return Err(io::Error::other("invalid Unix peer credentials"));
    }
    Ok(Credentials {
        pid: value.pid,
        uid: value.uid,
        gid: value.gid,
    })
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments, pointers or preconditions.
    unsafe { libc::geteuid() }
}
