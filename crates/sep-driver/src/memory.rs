//! Dedicated locked, dump-excluded memory for ioctl plaintext delivery.
//! This does not cover copies made by a caller or a cryptographic library.

use std::io;
use std::ptr::NonNull;
use zeroize::Zeroize;

use crate::MAX_BLOB;

pub fn make_process_nondumpable() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes a scalar argument and no pointers. Call after
    // setting final credentials; later credential changes can reset this policy.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct SecretBuffer {
    pointer: NonNull<u8>,
    mapped_len: usize,
}

impl SecretBuffer {
    /// Creates its final allocation and installs protections before secret input.
    /// Any failed protection aborts allocation, with no unprotected fallback.
    pub fn new() -> io::Result<Self> {
        // SAFETY: sysconf with _SC_PAGESIZE takes no caller-owned memory.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::other("cannot determine runtime page size"));
        }
        let page = page as usize;
        let mapped_len = MAX_BLOB.div_ceil(page) * page;
        // SAFETY: anonymous private mapping, kernel-selected address, no file or
        // inherited allocation. The returned mapping is exclusively owned here.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(pointer) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: mmap succeeded; dispose the complete allocation even if at zero.
            unsafe {
                libc::munmap(raw, mapped_len);
            }
            return Err(io::Error::other("null secret allocation"));
        };
        let buffer = Self {
            pointer,
            mapped_len,
        };
        // SAFETY: pointer and length identify the entire live page-aligned mapping.
        if unsafe { libc::mlock(raw, mapped_len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: advice applies only to this owned whole-page mapping.
        if unsafe { libc::madvise(raw, mapped_len, libc::MADV_DONTDUMP) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: no child may inherit this secret mapping; the application must
        // still avoid fork/exec with live secrets, as crypto temporaries exist.
        if unsafe { libc::madvise(raw, mapped_len, libc::MADV_DONTFORK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; MAX_BLOB] {
        // SAFETY: mapping is writable, at least MAX_BLOB bytes, and exclusively
        // borrowed for the returned reference's lifetime. Alignment for u8 is 1.
        unsafe { &mut *self.pointer.as_ptr().cast::<[u8; MAX_BLOB]>() }
    }

    pub fn as_array(&self) -> &[u8; MAX_BLOB] {
        // SAFETY: mapping remains live and readable while self is borrowed.
        unsafe { &*self.pointer.as_ptr().cast::<[u8; MAX_BLOB]>() }
    }

    pub fn mapping_len(&self) -> usize {
        self.mapped_len
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // SAFETY: exclusively owned mapping remains writable until munmap below.
        let all = unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.mapped_len) };
        all.zeroize();
        // SAFETY: wipe precedes unlock/unmap; both cover the exact owned mapping.
        unsafe {
            libc::munlock(self.pointer.as_ptr().cast(), self.mapped_len);
            libc::munmap(self.pointer.as_ptr().cast(), self.mapped_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_mapping_is_locked_dump_excluded_and_not_inherited() {
        let mut buffer = SecretBuffer::new().unwrap_or_else(|e| panic!("secret allocation: {e}"));
        buffer.as_mut_array()[..32].fill(0xa5);
        let start = buffer.pointer.as_ptr() as usize;
        let header = format!("{start:x}-{:x}", start + buffer.mapping_len());
        let smaps =
            std::fs::read_to_string("/proc/self/smaps").unwrap_or_else(|e| panic!("smaps: {e}"));
        let section = smaps
            .split(&header)
            .nth(1)
            .unwrap_or_else(|| panic!("dedicated mapping absent"));
        let flags = section
            .lines()
            .find(|line| line.starts_with("VmFlags:"))
            .unwrap_or_else(|| panic!("mapping flags absent"));
        for flag in ["lo", "dd", "dc"] {
            assert!(
                flags.split_whitespace().any(|value| value == flag),
                "missing {flag}: {flags}"
            );
        }
        assert_eq!(&buffer.as_array()[..32], &[0xa5; 32]);
    }
}
