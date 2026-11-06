use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::paths::AppPaths;
use crate::{Error, Result};

const ALLOWED_HEADERS: &[&str] = &[
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-I-SRL-NO",
    "X-Apple-I-Client-Time",
    "X-Apple-I-TimeZone",
    "X-Apple-Locale",
    "X-Mme-Client-Info",
    "X-Mme-Device-Id",
];
const MAX_HEADER_RESPONSE: u64 = 64 * 1024;

pub trait AnisetteProvider {
    fn headers(&self) -> Result<BTreeMap<String, String>>;
    fn resync(&self, _sim: &str) -> Result<()> {
        Err(Error::Apple(
            "this anisette provider cannot answer Apple's explicit resync request".into(),
        ))
    }
    /// ADI material and machine metadata, without the helper's suggested client
    /// profile. Each Apple service chooses its own endpoint-appropriate identity.
    fn validation_headers(&self) -> Result<BTreeMap<String, String>> {
        let mut headers = self.headers()?;
        headers.retain(|name, _| !name.eq_ignore_ascii_case("X-Mme-Client-Info"));
        Ok(headers)
    }
}

pub fn validate_helper(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::Config(
            "anisette helper must be supplied as an absolute path".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| Error::io(path, error))?;
    let metadata = fs::metadata(&canonical).map_err(|error| Error::io(&canonical, error))?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "{} is not a regular file",
            canonical.display()
        )));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(Error::Config(format!(
            "{} is not executable",
            canonical.display()
        )));
    }
    Ok(canonical)
}

pub fn setup(helper: &Path, paths: &AppPaths) -> Result<()> {
    let helper = validate_helper(helper)?;
    ensure_anisette_dir(paths)?;
    let mut child = Command::new(&helper)
        .arg("--adi-path")
        .arg(paths.anisette_dir())
        .arg("--skip-server-startup")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::io(&helper, error))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| Error::io(&helper, error))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(Error::Apple(format!(
                    "anisette setup helper exited with {status}"
                )))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Apple(
                "anisette setup did not finish within 60 seconds".into(),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub struct ManagedAnisette {
    endpoint: String,
    child: Child,
    client: Client,
}

impl ManagedAnisette {
    pub fn start(helper: &Path, paths: &AppPaths) -> Result<Self> {
        Self::start_with_image(helper, paths, None)
    }

    /// A service can keep the public Apple image outside its private mutable
    /// ADI state. Helper/image trust checks belong to its root-controlled setup.
    pub fn start_with_image(helper: &Path, paths: &AppPaths, image: Option<&Path>) -> Result<Self> {
        let helper = validate_helper(helper)?;
        ensure_anisette_dir(paths)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| Error::io(paths.runtime_dir.join("anisette-port"), error))?;
        let port = listener
            .local_addr()
            .map_err(|error| Error::io(paths.runtime_dir.join("anisette-port"), error))?
            .port();
        drop(listener);
        // The new local Mac adapter requires this per-launch nonce. Older
        // compatible helpers ignore the extra header/environment variable.
        let nonce = zeroize::Zeroizing::new(format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ));
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", nonce.as_str()))
            .map_err(|_| Error::InvalidData("invalid local anisette authorization".into()))?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .default_headers(HeaderMap::from_iter([(AUTHORIZATION, authorization)]))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut command = Command::new(&helper);
        command
            .env_remove("CREDENTIALS_DIRECTORY")
            .env_remove("ENCRYPTED_CREDENTIALS_DIRECTORY")
            .env("KEYCHAIN_ANISETTE_NONCE", nonce.as_str())
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--adi-path")
            .arg(paths.anisette_dir())
            .stdin(Stdio::null())
            // The upstream helper logs raw authentication headers at INFO.
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(image) = image {
            command.arg("--coreadi").arg(image);
        }
        let child = command.spawn().map_err(|error| Error::io(&helper, error))?;
        let mut managed = Self {
            endpoint: format!("http://127.0.0.1:{port}/"),
            child,
            client,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = managed
                .child
                .try_wait()
                .map_err(|error| Error::io(&helper, error))?
            {
                return Err(Error::Apple(format!(
                    "anisette helper exited during startup with {status}"
                )));
            }
            if managed.headers().is_ok() {
                return Ok(managed);
            }
            if Instant::now() >= deadline {
                return Err(Error::Apple(
                    "anisette helper did not become ready within 20 seconds".into(),
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl AnisetteProvider for ManagedAnisette {
    fn resync(&self, sim: &str) -> Result<()> {
        if sim.is_empty() || sim.len() > 4096 {
            return Err(Error::InvalidData(
                "anisette resync data exceeds bounds".into(),
            ));
        }
        let response = self
            .client
            .post(format!("{}v1/resync", self.endpoint))
            .timeout(Duration::from_secs(45))
            .json(&serde_json::json!({"sim":sim}))
            .send()?;
        if !response.status().is_success() {
            return Err(Error::Apple(format!(
                "anisette resync returned HTTP {}",
                response.status()
            )));
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        response
            .take(MAX_HEADER_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::io("anisette resync", error))?;
        if bytes.len() as u64 > MAX_HEADER_RESPONSE {
            return Err(Error::InvalidData(
                "anisette resync response exceeds bounds".into(),
            ));
        }
        let result: serde_json::Value = serde_json::from_slice(&bytes)?;
        if result.get("resynced").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(Error::Apple("anisette resync was not confirmed".into()));
        }
        Ok(())
    }

    fn headers(&self) -> Result<BTreeMap<String, String>> {
        let response = self.client.get(&self.endpoint).send()?;
        if !response.status().is_success() {
            return Err(Error::Apple(format!(
                "anisette helper returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HEADER_RESPONSE)
        {
            return Err(Error::InvalidData(
                "anisette response exceeds size limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_HEADER_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::io("anisette response", error))?;
        if bytes.len() as u64 > MAX_HEADER_RESPONSE {
            return Err(Error::InvalidData(
                "anisette response exceeds size limit".into(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let object = value
            .as_object()
            .ok_or_else(|| Error::InvalidData("anisette response is not an object".into()))?;
        let mut headers = BTreeMap::new();
        for allowed in ALLOWED_HEADERS {
            if let Some(value) = object
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(allowed))
                .and_then(|(_, value)| value.as_str())
            {
                headers.insert((*allowed).to_owned(), value.to_owned());
            }
        }
        if !headers.contains_key("X-Apple-I-MD") || !headers.contains_key("X-Apple-I-MD-M") {
            return Err(Error::InvalidData(
                "anisette helper did not return X-Apple-I-MD and X-Apple-I-MD-M".into(),
            ));
        }
        Ok(headers)
    }
}

impl Drop for ManagedAnisette {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ensure_anisette_dir(paths: &AppPaths) -> Result<()> {
    let path = paths.anisette_dir();
    fs::create_dir_all(&path).map_err(|error| Error::io(&path, error))?;
    let metadata = fs::symlink_metadata(&path).map_err(|error| Error::io(&path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Security(format!(
            "{} must be a real directory, not a symlink",
            path.display()
        )));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::io(&path, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_device_id_is_forwarded_with_its_machine_data() {
        assert!(ALLOWED_HEADERS.contains(&"X-Mme-Device-Id"));
    }
}
