//! Root-operation / unprivileged-session presentation protocol.
//! The agent can acknowledge display or cancel; it can never grant authorization.
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

const MAX_FRAME: usize = 8192;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub id: Uuid,
    pub application: String,
    pub action: String,
    pub account: String,
}
impl Presentation {
    pub fn validate(&self) -> io::Result<()> {
        if self.id.is_nil()
            || self.application.is_empty()
            || self.action.is_empty()
            || [&self.application, &self.action, &self.account]
                .iter()
                .any(|s| s.len() > 512 || s.chars().any(char::is_control))
        {
            return Err(io::Error::other("invalid prompt presentation"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DisplayEvent {
    Present { version: u32, request: Presentation },
    Status { id: Uuid, message: String },
    Finished { id: Uuid },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AgentEvent {
    Visible { id: Uuid },
    Cancel { id: Uuid },
}

pub fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::other("prompt message too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)
}
pub fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::other("invalid prompt frame size"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub struct PromptSession {
    stream: UnixStream,
    id: Uuid,
    canceled: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl PromptSession {
    /// The trusted caller supplies the owner derived from authenticated session
    /// state. Diagnostic callers may supply it explicitly; production clients may not.
    pub fn connect(path: &Path, owner: u32, request: Presentation) -> io::Result<Self> {
        if keychain_sep_driver::peer::effective_uid() != 0 {
            return Err(io::Error::other(
                "prompt caller must be the privileged operation service",
            ));
        }
        request.validate()?;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket()
            || meta.uid() != owner
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "prompt socket must be private and owned by the selected user",
            ));
        }
        let mut stream = UnixStream::connect(path)?;
        if keychain_sep_driver::peer::credentials(&stream)?.uid != owner {
            return Err(io::Error::other("wrong prompt-agent owner"));
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        let id = request.id;
        write_frame(
            &mut stream,
            &DisplayEvent::Present {
                version: 1,
                request,
            },
        )?;
        match read_frame(&mut stream)? {
            AgentEvent::Visible { id: received } if received == id => (),
            _ => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(io::Error::other("prompt was not presented"));
            }
        }
        stream.set_read_timeout(None)?;
        let mut input = stream.try_clone()?;
        let canceled = Arc::new(AtomicBool::new(false));
        let signal = canceled.clone();
        let reader = std::thread::spawn(move || {
            // Any message, malformed input, or disconnect terminates permission
            // to continue. There is intentionally no agent-success variant.
            let _: io::Result<AgentEvent> = read_frame(&mut input);
            signal.store(true, Ordering::Release);
        });
        Ok(Self {
            stream,
            id,
            canceled,
            reader: Some(reader),
        })
    }
    pub fn canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
    pub fn status(&mut self, message: &str) -> io::Result<()> {
        if message.len() > 512 || message.chars().any(char::is_control) {
            return Err(io::Error::other("invalid status"));
        }
        write_frame(
            &mut self.stream,
            &DisplayEvent::Status {
                id: self.id,
                message: message.into(),
            },
        )
    }
}
impl Drop for PromptSession {
    fn drop(&mut self) {
        let _ = write_frame(&mut self.stream, &DisplayEvent::Finished { id: self.id });
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_bounds_and_agent_success_are_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        a.write_all(&9000_u32.to_le_bytes())
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert!(read_frame::<AgentEvent>(&mut b).is_err());
        assert!(
            serde_json::from_str::<AgentEvent>(
                r#"{"event":"success","id":"00000000-0000-0000-0000-000000000001"}"#
            )
            .is_err()
        );
    }
    #[test]
    fn peer_identity_comes_from_kernel() {
        let (a, _) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        let peer =
            keychain_sep_driver::peer::credentials(&a).unwrap_or_else(|e| panic!("peer: {e}"));
        assert_eq!(peer.uid, keychain_sep_driver::peer::effective_uid());
        assert_eq!(peer.pid as u32, std::process::id());
    }
}
