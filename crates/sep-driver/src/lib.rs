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
pub mod memory;
pub mod peer;

pub const MAX_BLOB: usize = 4096;
pub const MAX_SIGNATURE: usize = 72;
const GET_INFO: libc::c_ulong = 0x8020_b101;
const CANCEL: libc::c_ulong = 0xb107;
const CREATE: libc::c_ulong = 0xc058_b10b;
const SIGN_START: libc::c_ulong = 0x4038_b10c;
const SIGN_POLL: libc::c_ulong = 0x8058_b10d;
const DECRYPT_START: libc::c_ulong = 0x4020_b10e;
const DECRYPT_POLL: libc::c_ulong = 0xc018_b10f;

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
    pub sensor_present: u32,
    pub enrolled: u32,
    pub capacity: u32,
    pub enroll_stages: u32,
    pub reserved: [u32; 3],
}

#[repr(C)]
struct Create {
    flags: u32,
    blob_len: u32,
    blob_ptr: u64,
    public: [u8; 65],
    reserved: [u8; 7],
}
#[repr(C)]
struct SignStart {
    flags: u32,
    timeout_ms: u32,
    blob_len: u32,
    reserved: u32,
    blob_ptr: u64,
    digest: [u8; 32],
}
#[repr(C)]
struct SignPoll {
    state: u32,
    status: i32,
    guidance: u32,
    sig_len: u32,
    signature: [u8; 72],
}
#[repr(C)]
struct DecryptStart {
    flags: u32,
    timeout_ms: u32,
    blob_len: u32,
    sealed_len: u32,
    blob_ptr: u64,
    sealed_ptr: u64,
}
#[repr(C)]
struct DecryptPoll {
    state: u32,
    status: i32,
    guidance: u32,
    plain_len: u32,
    plain_ptr: u64,
}

const _: () = {
    assert!(size_of::<Info>() == 32);
    assert!(size_of::<Create>() == 88);
    assert!(size_of::<SignStart>() == 56);
    assert!(size_of::<SignPoll>() == 88);
    assert!(size_of::<DecryptStart>() == 32);
    assert!(size_of::<DecryptPoll>() == 24);
};

pub struct CreatedKey {
    pub wrapped_blob: Vec<u8>,
    pub public: [u8; 65],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guidance {
    WaitingForDevice,
    Preparing,
    PlaceFinger,
    LiftAndMove,
    HoldStill,
}

/// Owns the exclusive device open. Dropping an active operation cancels delivery.
pub struct Device {
    file: File,
    info: Info,
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
        if info.version != 4 || info.reserved[0] & 2 == 0 {
            return Err(Error::Unsupported);
        }
        Ok(Self { file, info })
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    pub fn create(&mut self, decrypt: bool) -> Result<CreatedKey> {
        let mut blob = vec![0; MAX_BLOB];
        let mut request = Create {
            flags: u32::from(decrypt),
            blob_len: MAX_BLOB as u32,
            blob_ptr: blob.as_mut_ptr() as u64,
            public: [0; 65],
            reserved: [0; 7],
        };
        ioctl(&self.file, CREATE, &mut request).map_err(Error::Io)?;
        if request.blob_len == 0 || request.blob_len as usize > MAX_BLOB || request.public[0] != 4 {
            return Err(Error::InvalidResponse);
        }
        blob.truncate(request.blob_len as usize);
        Ok(CreatedKey {
            wrapped_blob: blob,
            public: request.public,
        })
    }

    /// Callback observes guidance and returns false to cancel. The driver consumes
    /// the digest unchanged; callers hashing messages must do so exactly once.
    pub fn sign_digest(
        &mut self,
        blob: &[u8],
        digest: &[u8; 32],
        timeout: Duration,
        mut progress: impl FnMut(Guidance) -> bool,
    ) -> Result<Vec<u8>> {
        let timeout_ms = validate(blob, timeout)?;
        let deadline = Instant::now() + timeout;
        let mut request = SignStart {
            flags: 0,
            timeout_ms,
            blob_len: blob.len() as u32,
            reserved: 0,
            blob_ptr: blob.as_ptr() as u64,
            digest: *digest,
        };
        let mut operation = Operation::new(&self.file);
        ioctl(&self.file, SIGN_START, &mut request).map_err(start_error)?;
        loop {
            operation.check(deadline)?;
            let mut response = SignPoll {
                state: 0,
                status: 0,
                guidance: 0,
                sig_len: 0,
                signature: [0; 72],
            };
            ioctl(&self.file, SIGN_POLL, &mut response).map_err(Error::Ambiguous)?;
            if terminal(response.state, response.status)? {
                operation.check(deadline)?;
                if !(1..=MAX_SIGNATURE).contains(&(response.sig_len as usize)) {
                    return Err(Error::InvalidResponse);
                }
                operation.finished = true;
                return Ok(response.signature[..response.sig_len as usize].to_vec());
            }
            if !progress(guidance(response.guidance)?) {
                return Err(Error::Canceled);
            }
            operation.wait(deadline)?;
        }
    }

    /// Plaintext is written only to the caller-owned fixed buffer; errors erase it.
    /// Caller MUST erase successful output after its authorized use.
    pub fn decrypt_into(
        &mut self,
        blob: &[u8],
        sealed: &[u8],
        output: &mut [u8; MAX_BLOB],
        timeout: Duration,
        mut progress: impl FnMut(Guidance) -> bool,
    ) -> Result<usize> {
        output.zeroize();
        let result = (|| {
            let timeout_ms = validate(blob, timeout)?;
            if !(81..=MAX_BLOB).contains(&sealed.len()) || sealed[0] != 4 {
                return Err(Error::InvalidInput);
            }
            let deadline = Instant::now() + timeout;
            let mut request = DecryptStart {
                flags: 0,
                timeout_ms,
                blob_len: blob.len() as u32,
                sealed_len: sealed.len() as u32,
                blob_ptr: blob.as_ptr() as u64,
                sealed_ptr: sealed.as_ptr() as u64,
            };
            let mut operation = Operation::new(&self.file);
            ioctl(&self.file, DECRYPT_START, &mut request).map_err(start_error)?;
            loop {
                operation.check(deadline)?;
                // Rebuild capacity on every poll: pending responses may set it to zero.
                let mut response = DecryptPoll {
                    state: 0,
                    status: 0,
                    guidance: 0,
                    plain_len: MAX_BLOB as u32,
                    plain_ptr: output.as_mut_ptr() as u64,
                };
                ioctl(&self.file, DECRYPT_POLL, &mut response).map_err(Error::Ambiguous)?;
                if terminal(response.state, response.status)? {
                    operation.check(deadline)?;
                    if response.plain_len as usize > MAX_BLOB {
                        return Err(Error::InvalidResponse);
                    }
                    operation.finished = true;
                    return Ok(response.plain_len as usize);
                }
                if !progress(guidance(response.guidance)?) {
                    return Err(Error::Canceled);
                }
                operation.wait(deadline)?;
            }
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
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
fn guidance(value: u32) -> Result<Guidance> {
    match value {
        0 => Ok(Guidance::Preparing),
        1 => Ok(Guidance::PlaceFinger),
        2 => Ok(Guidance::LiftAndMove),
        3 => Ok(Guidance::HoldStill),
        _ => Err(Error::InvalidResponse),
    }
}
fn terminal(state: u32, status: i32) -> Result<bool> {
    match (state, status) {
        (3, 0) => Ok(true),
        (1 | 2, 0) => Ok(false),
        (4, code) if (-4095..0).contains(&code) => {
            Err(Error::Io(io::Error::from_raw_os_error(-code)))
        }
        _ => Err(Error::InvalidResponse),
    }
}
fn start_error(error: io::Error) -> Error {
    if matches!(error.raw_os_error(), Some(libc::EINTR | libc::EIO)) {
        Error::Ambiguous(error)
    } else {
        Error::Io(error)
    }
}

// Private: called only with the initialized repr(C) records above. They contain
// no implicit padding, and all embedded pointer targets outlive this synchronous
// call. The driver copies START inputs before returning, as specified by the ABI.
fn ioctl<T>(file: &File, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    // SAFETY: callers supply the exact record for this ioctl, with valid bounded
    // pointer targets. The mutable borrow prevents concurrent record access.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, value as *mut T) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct Operation<'a> {
    file: &'a File,
    finished: bool,
}
impl<'a> Operation<'a> {
    fn new(file: &'a File) -> Self {
        Self {
            file,
            finished: false,
        }
    }
    fn check(&self, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
    fn wait(&self, deadline: Instant) -> Result<()> {
        self.check(deadline)?;
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 100) as i32;
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live initialized pollfd, accessible for the duration of poll.
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 {
            return Err(Error::Ambiguous(io::Error::last_os_error()));
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::Ambiguous(io::Error::from_raw_os_error(libc::ENODEV)));
        }
        Ok(())
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: CANCEL takes no pointer and the descriptor remains live.
            let _ = unsafe { libc::ioctl(self.file.as_raw_fd(), CANCEL) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_states_and_bounds_fail_closed() {
        assert!(terminal(3, -5).is_err());
        assert!(terminal(4, 0).is_err());
        assert!(terminal(0, 0).is_err());
        assert!(terminal(4, i32::MIN).is_err());
        assert!(terminal(1, 0).is_ok());
        assert!(validate(&[], Duration::from_secs(1)).is_err());
        assert!(validate(&[1], Duration::ZERO).is_err());
        assert!(validate(&[1], Duration::from_secs(121)).is_err());
    }

    #[test]
    fn layouts_and_ioctl_numbers_match_the_supplied_c_header() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let binary = dir.path().join("abi");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let compile = std::process::Command::new("cc")
            .arg(root.join("tests/abi.c"))
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap_or_else(|e| panic!("C compiler: {e}"));
        assert!(compile.success());
        let output = std::process::Command::new(binary)
            .output()
            .unwrap_or_else(|e| panic!("ABI probe: {e}"));
        assert!(output.status.success());
        let expected = format!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
            size_of::<Info>(),
            size_of::<Create>(),
            size_of::<SignStart>(),
            size_of::<SignPoll>(),
            size_of::<DecryptStart>(),
            size_of::<DecryptPoll>(),
            GET_INFO,
            CREATE,
            SIGN_START,
            SIGN_POLL,
            CANCEL,
            DECRYPT_START,
            DECRYPT_POLL,
            std::mem::offset_of!(Create, public),
            std::mem::offset_of!(SignStart, digest),
            std::mem::offset_of!(DecryptPoll, plain_ptr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    }
}
