//! Safe ownership wrapper for the local SEP biometric application-key ABI.
//! This crate is the only application component that performs raw device ioctls.

#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
)))]
compile_error!("the reviewed SEP ABI requires 64-bit little-endian Linux");

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroize;
pub mod clock;
pub mod memory;
pub mod peer;

// Generated directly from include/linux/apple-sep.h at build time. The same
// probe emits compile-time assertions for every pointer-bearing record layout.
include!(concat!(env!("OUT_DIR"), "/abi.rs"));
pub const MAX_BLOB: usize = BLOB_CAPACITY as usize;
pub const MAX_SIGNATURE: usize = SIGNATURE_CAPACITY as usize;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Unsupported,
    InvalidInput,
    InvalidResponse,
    Canceled,
    Expired,
    /// The operation may have reached hardware. Never retry automatically.
    Ambiguous(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "SEP device: {e}"),
            Self::Unsupported => f.write_str("SEP application-key API unavailable"),
            Self::InvalidInput => f.write_str("invalid SEP operation input"),
            Self::InvalidResponse => f.write_str("invalid SEP driver response"),
            Self::Canceled => f.write_str("SEP operation canceled"),
            Self::Expired => f.write_str("SEP operation expired"),
            Self::Ambiguous(e) => write!(f, "SEP completion unknown: {e}"),
        }
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

#[repr(C)]
#[derive(Default)]
pub struct Info {
    pub version: u32,
    pub capabilities: u32,
    pub reserved: [u32; 2],
}
impl Info {
    pub fn signing(&self) -> bool {
        self.capabilities & CAP_SIGN as u32 != 0
    }
    pub fn decryption(&self) -> bool {
        self.capabilities & CAP_DECRYPT as u32 != 0
    }
    fn validate(&self) -> Result<()> {
        if self.version != IFACE_VERSION as u32 || self.reserved != [0; 2] {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
#[repr(C)]
struct Create {
    flags: u32,
    blob_len: u32,
    blob_ptr: u64,
    public_key: [u8; 65],
    reserved: [u8; 7],
}
#[repr(C)]
struct Sign {
    request_id: u64,
    flags: u32,
    timeout_ms: u32,
    blob_len: u32,
    sig_len: u32,
    blob_ptr: u64,
    digest: [u8; 32],
    signature: [u8; MAX_SIGNATURE],
}
#[repr(C)]
struct Decrypt {
    request_id: u64,
    flags: u32,
    timeout_ms: u32,
    blob_len: u32,
    sealed_len: u32,
    blob_ptr: u64,
    sealed_ptr: u64,
    plain_len: u32,
    reserved: u32,
    plain_ptr: u64,
}
#[repr(C)]
struct Cancel {
    request_id: u64,
}

pub struct CreatedKey {
    pub wrapped_blob: Vec<u8>,
    pub public: [u8; 65],
}

/// Application status only: the blocking ABI exposes no sensor guidance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guidance {
    WaitingForDevice,
    Preparing,
    PlaceFinger,
}

/// One logical operation per owned file. The scoped caller and control thread
/// share this exact File; cancellation never opens a second device descriptor.
pub struct Device {
    file: File,
    info: Info,
    next_id: Option<u64>,
}

impl Device {
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(Error::Io)?;
        if !file
            .metadata()
            .map_err(Error::Io)?
            .file_type()
            .is_char_device()
        {
            return Err(Error::InvalidInput);
        }
        let mut info = Info::default();
        ioctl(&file, GET_INFO, &mut info).map_err(Error::Io)?;
        info.validate()?;
        Ok(Self {
            file,
            info,
            next_id: Some(1),
        })
    }
    pub fn info(&self) -> &Info {
        &self.info
    }
    fn require(&self, capabilities: u64) -> Result<()> {
        if self.info.capabilities & capabilities as u32 != capabilities as u32 {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    fn request_id(&mut self) -> Result<u64> {
        allocate_id(&mut self.next_id)
    }
    pub fn create(&mut self, decrypt: bool) -> Result<CreatedKey> {
        self.require(if decrypt {
            CAP_SIGN | CAP_DECRYPT
        } else {
            CAP_SIGN
        })?;
        let mut blob = vec![0; MAX_BLOB];
        let mut request = Create {
            flags: if decrypt { CREATE_DECRYPT as u32 } else { 0 },
            blob_len: MAX_BLOB as u32,
            blob_ptr: blob.as_mut_ptr() as u64,
            public_key: [0; 65],
            reserved: [0; 7],
        };
        // CREATE has no private request ID or scan, and is never retried.
        ioctl(&self.file, CREATE, &mut request).map_err(private_error)?;
        if request.blob_len == 0
            || request.blob_len as usize > MAX_BLOB
            || request.public_key[0] != 4
            || request.reserved != [0; 7]
        {
            return Err(Error::InvalidResponse);
        }
        blob.truncate(request.blob_len as usize);
        Ok(CreatedKey {
            wrapped_blob: blob,
            public: request.public_key,
        })
    }

    /// A dedicated thread makes exactly one blocking SIGN. The calling/control
    /// thread checks application authorization independently of driver progress
    /// and can issue CANCEL on this file while SIGN is asleep. The digest is
    /// already SHA-256; it is never hashed again here.
    pub fn sign_digest(
        &mut self,
        blob: &[u8],
        digest: &[u8; 32],
        timeout: Duration,
        mut authorized: impl FnMut(Guidance) -> bool,
    ) -> Result<Vec<u8>> {
        self.require(CAP_SIGN)?;
        let timeout_ms = validate(blob, timeout)?;
        let id = self.request_id()?;
        let mut request = Sign {
            request_id: id,
            flags: 0,
            timeout_ms,
            blob_len: blob.len() as u32,
            sig_len: 0,
            blob_ptr: blob.as_ptr() as u64,
            digest: *digest,
            signature: [0; MAX_SIGNATURE],
        };
        let result = controlled(
            &self.file,
            id,
            Instant::now() + timeout,
            &mut authorized,
            || ioctl(&self.file, SIGN, &mut request).map_err(private_error),
            cancel,
        );
        let result = result.and_then(|()| {
            if !(1..=MAX_SIGNATURE).contains(&(request.sig_len as usize)) {
                return Err(Error::InvalidResponse);
            }
            Ok(request.signature[..request.sig_len as usize].to_vec())
        });
        request.signature.zeroize();
        result
    }

    /// The ioctl writes directly into the caller's fixed, protected mapping.
    /// Errors (including descriptor-copy faults and raced success after revoke)
    /// wipe the WHOLE destination. The caller must wipe successful output.
    pub fn decrypt_into(
        &mut self,
        blob: &[u8],
        sealed: &[u8],
        output: &mut [u8; MAX_BLOB],
        timeout: Duration,
        mut authorized: impl FnMut(Guidance) -> bool,
    ) -> Result<usize> {
        let mut output = OutputGuard::new(output);
        let result = (|| {
            self.require(CAP_DECRYPT)?;
            let timeout_ms = validate(blob, timeout)?;
            if !(81..=MAX_BLOB).contains(&sealed.len()) || sealed[0] != 4 {
                return Err(Error::InvalidInput);
            }
            let id = self.request_id()?;
            let mut request = Decrypt {
                request_id: id,
                flags: 0,
                timeout_ms,
                blob_len: blob.len() as u32,
                sealed_len: sealed.len() as u32,
                blob_ptr: blob.as_ptr() as u64,
                sealed_ptr: sealed.as_ptr() as u64,
                plain_len: MAX_BLOB as u32,
                reserved: 0,
                plain_ptr: output.buffer.as_mut_ptr() as u64,
            };
            controlled(
                &self.file,
                id,
                Instant::now() + timeout,
                &mut authorized,
                || ioctl(&self.file, DECRYPT, &mut request).map_err(private_error),
                cancel,
            )?;
            if request.plain_len as usize > MAX_BLOB || request.reserved != 0 {
                return Err(Error::InvalidResponse);
            }
            Ok(request.plain_len as usize)
        })();
        if result.is_ok() {
            output.success = true;
        }
        result
    }
}

fn allocate_id(next: &mut Option<u64>) -> Result<u64> {
    let id = next
        .take()
        .filter(|id| *id != 0)
        .ok_or(Error::InvalidInput)?;
    *next = id.checked_add(1);
    Ok(id)
}
fn validate(blob: &[u8], timeout: Duration) -> Result<u32> {
    if blob.is_empty()
        || blob.len() > MAX_BLOB
        || timeout < Duration::from_millis(1)
        || timeout > Duration::from_secs(120)
    {
        return Err(Error::InvalidInput);
    }
    Ok(timeout.as_millis() as u32)
}
fn private_error(error: io::Error) -> Error {
    if matches!(
        error.raw_os_error(),
        Some(libc::EINTR | libc::EIO | libc::EFAULT | libc::ENOSPC)
    ) {
        Error::Ambiguous(error)
    } else {
        Error::Io(error)
    }
}

// No EINTR loop: every private operation is submitted exactly once. Pointer
// targets and file lifetime are held through the scoped caller's join.
fn ioctl<T>(file: &File, request: u64, value: &mut T) -> io::Result<()> {
    // SAFETY: each private caller supplies the matching repr(C) ABI record;
    // pointed-to bounded buffers outlive the call and are not accessed during it.
    let result =
        unsafe { libc::ioctl(file.as_raw_fd(), request as libc::c_ulong, value as *mut T) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn cancel(file: &File, id: u64) -> io::Result<()> {
    ioctl(file, CANCEL, &mut Cancel { request_id: id })
}

struct OutputGuard<'a> {
    buffer: &'a mut [u8; MAX_BLOB],
    success: bool,
}
impl<'a> OutputGuard<'a> {
    fn new(buffer: &'a mut [u8; MAX_BLOB]) -> Self {
        buffer.zeroize();
        Self {
            buffer,
            success: false,
        }
    }
}
impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.success {
            self.buffer.zeroize();
        }
    }
}

struct CancelOnDrop<'a, C: Fn(&File, u64) -> io::Result<()>> {
    file: &'a File,
    id: u64,
    cancel: &'a C,
    armed: bool,
    started: Instant,
}
impl<C: Fn(&File, u64) -> io::Result<()>> CancelOnDrop<'_, C> {
    fn revoke(&mut self) {
        // Application delivery is revoked BEFORE the cancellation syscall.
        self.armed = false;
        eprintln!(
            "SEP request {} cancel entry elapsed_us={}",
            self.id,
            self.started.elapsed().as_micros()
        );
        let result = (self.cancel)(self.file, self.id);
        eprintln!(
            "SEP request {} cancel exit errno={} elapsed_us={}",
            self.id,
            result.err().and_then(|e| e.raw_os_error()).unwrap_or(0),
            self.started.elapsed().as_micros()
        );
    }
}
impl<C: Fn(&File, u64) -> io::Result<()>> Drop for CancelOnDrop<'_, C> {
    fn drop(&mut self) {
        if self.armed {
            self.revoke();
        }
    }
}

/// Testable lifetime/control mechanism. No driver progress/result-retention
/// ioctls: the authorization callback runs on the control thread even while
/// execute blocks. Scoped joining also holds on callback panic. No automatic
/// busy/interrupted retry. A terminal driver failure retains its original errno.
fn controlled<R: Send>(
    file: &File,
    id: u64,
    deadline: Instant,
    authorized: &mut impl FnMut(Guidance) -> bool,
    execute: impl FnOnce() -> Result<R> + Send,
    cancel: impl Fn(&File, u64) -> io::Result<()>,
) -> Result<R> {
    let started = Instant::now();
    let mut guard = CancelOnDrop {
        file,
        id,
        cancel: &cancel,
        armed: true,
        started,
    };
    // ID is already allocated. Early revoke retires it before dispatch.
    if !authorized(Guidance::PlaceFinger) {
        guard.revoke();
        return Err(Error::Canceled);
    }
    if Instant::now() >= deadline {
        guard.revoke();
        return Err(Error::Expired);
    }
    std::thread::scope(|scope| {
        let caller = std::thread::Builder::new()
            .name("sep-key-call".into())
            .spawn_scoped(scope, || {
                eprintln!(
                    "SEP request {id} ioctl entry elapsed_us={}",
                    started.elapsed().as_micros()
                );
                let result = execute();
                let errno = match &result {
                    Err(Error::Io(e) | Error::Ambiguous(e)) => e.raw_os_error().unwrap_or(0),
                    _ => 0,
                };
                eprintln!(
                    "SEP request {id} ioctl exit errno={errno} elapsed_us={}",
                    started.elapsed().as_micros()
                );
                result
            })
            .map_err(Error::Io)?;
        // This guard must unwind BEFORE the scope joins its worker, so a
        // panicking callback cannot leave a blocked ioctl awaiting a finger.
        let mut guard = guard;
        let mut revoked = None;
        while !caller.is_finished() {
            if !authorized(Guidance::PlaceFinger) {
                revoked = Some(Error::Canceled);
            } else if Instant::now() >= deadline {
                revoked = Some(Error::Expired);
            }
            if revoked.is_some() {
                guard.revoke();
                break;
            }
            std::thread::park_timeout(Duration::from_millis(25));
        }
        let result = caller.join().unwrap_or(Err(Error::InvalidResponse));
        // A result claimed just before CANCEL, ENOENT or EALREADY still cannot
        // be delivered after broker/UI revocation. Recheck even a fast success.
        if revoked.is_none() {
            if !authorized(Guidance::PlaceFinger) {
                revoked = Some(Error::Canceled);
            } else if Instant::now() >= deadline {
                revoked = Some(Error::Expired);
            }
            if revoked.is_some() {
                guard.revoke();
            }
        }
        guard.armed = false;
        eprintln!(
            "SEP request {id} caller joined revoked={} elapsed_us={}",
            revoked.is_some(),
            started.elapsed().as_micros()
        );
        match result {
            Err(error) => Err(error), // preserve EIO/EINTR even when UI canceled
            Ok(_) if revoked.is_some() => Err(revoked.unwrap_or(Error::Canceled)),
            Ok(value) => Ok(value),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };

    fn file() -> File {
        File::open("/dev/null").unwrap_or_else(|e| panic!("file: {e}"))
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn capability_version_and_request_ids_fail_closed() {
        assert!(
            Info {
                version: 1,
                capabilities: 0,
                reserved: [0; 2]
            }
            .validate()
            .is_ok()
        );
        assert!(
            Info {
                version: 4,
                ..Info::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Info {
                version: 1,
                reserved: [1, 0],
                ..Info::default()
            }
            .validate()
            .is_err()
        );
        let mut next = Some(1);
        assert_eq!(allocate_id(&mut next).unwrap_or(0), 1);
        assert_eq!(allocate_id(&mut next).unwrap_or(0), 2);
        next = Some(u64::MAX);
        assert_eq!(allocate_id(&mut next).unwrap_or(0), u64::MAX);
        assert!(allocate_id(&mut next).is_err());
        next = Some(0);
        assert!(allocate_id(&mut next).is_err());
        assert!(validate(&[], Duration::from_secs(1)).is_err());
        assert!(validate(&[1], Duration::ZERO).is_err());
        assert!(validate(&[1], Duration::from_secs(121)).is_err());
    }

    #[test]
    fn cancellation_runs_on_same_file_while_execute_is_blocked_and_joins() {
        let file = file();
        let entered = AtomicBool::new(false);
        let joined = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);
        let (release, wait) = mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let result = controlled(
            &file,
            9,
            deadline(),
            &mut |_| !entered.load(Ordering::Acquire),
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                entered.store(true, Ordering::Release);
                wait.lock()
                    .unwrap_or_else(|e| panic!("wait: {e}"))
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_else(|e| panic!("cancel was not concurrent: {e}"));
                joined.store(true, Ordering::Release);
                // Simulate a result claimed just before cancellation.
                Ok(vec![1, 2, 3])
            },
            |same_file, id| {
                assert_eq!(same_file.as_raw_fd(), file.as_raw_fd());
                assert_eq!(id, 9);
                release.send(()).unwrap_or_else(|e| panic!("release: {e}"));
                Err(io::Error::from_raw_os_error(libc::EALREADY))
            },
        );
        assert!(matches!(result, Err(Error::Canceled)));
        assert!(joined.load(Ordering::Acquire));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn driver_errors_win_cancel_races_and_are_never_replayed() {
        for errno in [
            libc::EINTR,
            libc::EIO,
            libc::EFAULT,
            libc::ENOSPC,
            libc::EBUSY,
            libc::EACCES,
            libc::EOPNOTSUPP,
        ] {
            let entered = AtomicBool::new(false);
            let calls = AtomicUsize::new(0);
            let (release, wait) = mpsc::channel();
            let wait = std::sync::Mutex::new(wait);
            let result: Result<()> = controlled(
                &file(),
                1,
                deadline(),
                &mut |_| !entered.load(Ordering::Acquire),
                || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    entered.store(true, Ordering::Release);
                    wait.lock()
                        .unwrap_or_else(|e| panic!("wait: {e}"))
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap_or_else(|e| panic!("cancel: {e}"));
                    Err(private_error(io::Error::from_raw_os_error(errno)))
                },
                |_, _| {
                    release.send(()).unwrap_or_else(|e| panic!("release: {e}"));
                    Ok(())
                },
            );
            assert!(
                matches!(result, Err(Error::Io(e) | Error::Ambiguous(e)) if e.raw_os_error() == Some(errno))
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn predispatch_revoke_retires_id_without_submitting() {
        let retired = AtomicUsize::new(0);
        let result: Result<()> = controlled(
            &file(),
            7,
            deadline(),
            &mut |_| false,
            || panic!("revoked operation submitted"),
            |_, id| {
                retired.store(id as usize, Ordering::Relaxed);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Canceled)));
        assert_eq!(retired.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn deadline_cancels_sleeping_caller_and_discards_raced_plaintext() {
        let (release, wait) = mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let result = controlled(
            &file(),
            1,
            Instant::now() + Duration::from_millis(40),
            &mut |_| true,
            || {
                wait.lock()
                    .unwrap_or_else(|e| panic!("wait: {e}"))
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_else(|e| panic!("cancel: {e}"));
                Ok(())
            },
            |_, _| {
                release.send(()).unwrap_or_else(|e| panic!("release: {e}"));
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::Expired)));
    }

    #[test]
    fn final_authorization_check_revokes_fast_success() {
        let finished = AtomicBool::new(false);
        let result = controlled(
            &file(),
            1,
            deadline(),
            &mut |_| !finished.load(Ordering::Acquire),
            || {
                finished.store(true, Ordering::Release);
                Ok(())
            },
            |_, _| Err(io::Error::from_raw_os_error(libc::ENOENT)),
        );
        assert!(matches!(result, Err(Error::Canceled)));
    }

    #[test]
    fn callback_panic_cancels_before_join_and_wipes_partial_output() {
        let mut output = [0; MAX_BLOB];
        let entered = AtomicBool::new(false);
        let exited = AtomicBool::new(false);
        let (release, wait) = mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = OutputGuard::new(&mut output);
            let _: Result<()> = controlled(
                &file(),
                1,
                deadline(),
                &mut |_| {
                    assert!(!entered.load(Ordering::Acquire), "synthetic control panic");
                    true
                },
                || {
                    guard.buffer.fill(0x55); // partial copy before descriptor error
                    entered.store(true, Ordering::Release);
                    wait.lock()
                        .unwrap_or_else(|e| panic!("wait: {e}"))
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap_or_else(|e| panic!("cancel: {e}"));
                    exited.store(true, Ordering::Release);
                    Ok(())
                },
                |_, _| {
                    release.send(()).unwrap_or_else(|e| panic!("release: {e}"));
                    Ok(())
                },
            );
        }));
        assert!(result.is_err());
        assert!(exited.load(Ordering::Acquire));
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn failure_wipes_entire_output_but_success_is_caller_owned() {
        let mut buffer = [0x44; MAX_BLOB];
        {
            let guard = OutputGuard::new(&mut buffer);
            assert!(guard.buffer.iter().all(|byte| *byte == 0));
            guard.buffer[..20].fill(0x33);
        }
        assert!(buffer.iter().all(|byte| *byte == 0));
        {
            let mut guard = OutputGuard::new(&mut buffer);
            guard.buffer[..20].fill(0x33);
            guard.success = true;
        }
        assert_eq!(&buffer[..20], &[0x33; 20]);
        buffer.zeroize();
    }
}
