//! Small safe adapter for the Linux clock shared by presentation processes.
use std::io;

pub fn monotonic_nanoseconds() -> io::Result<u128> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a writable timespec; CLOCK_MONOTONIC takes no pointers
    // other than this output, and the result is checked before conversion.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(io::Error::other("invalid monotonic clock result"));
    }
    Ok(value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128)
}
