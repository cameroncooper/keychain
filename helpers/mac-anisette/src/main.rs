// SPDX-License-Identifier: GPL-2.0-only
//! Separate GPL helper process; the MIT keychain application does not link the
//! emulator. No Apple password, 2FA code, PET or vault key enters this process.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apple_core::anisette::{
    CoreAdiAnisette, DS_ID, MachineFile, MachineIdentity, provision_new_machine,
};
use apple_core::gsa::DEFAULT_CLIENT_INFO;
use apple_core::http::Http;
use apple_core::login::AnisetteSource;
use clap::Parser;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_STATE: u64 = 4 * 1024 * 1024;
const MAX_HTTP: usize = 8192;

#[derive(Parser)]
#[command(about = "Local macOS CoreADI emulator; no remote anisette server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    #[arg(long, default_value_t = 6969)]
    port: u16,
    #[arg(long)]
    adi_path: PathBuf,
    /// Public Apple CoreADI image; default: ADI_PATH/lib/CoreADI.
    #[arg(long)]
    coreadi: Option<PathBuf>,
    /// Explicit one-time setup. Normal startup never creates a new identity.
    #[arg(long)]
    skip_server_startup: bool,
    /// Check OTP freshness offline; prints no header values.
    #[arg(long, conflicts_with = "skip_server_startup")]
    check_clock: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Prepared,
    Ready,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    phase: Phase,
    machine_json: String,
}
impl Drop for State {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.machine_json);
    }
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("keychain-anisette-mac: {error}");
        std::process::exit(1);
    }
}

fn protect_process() -> io::Result<()> {
    // Linux process hardening only; no emulator/firmware pointer crosses this API.
    let parent = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent || parent == 1 {
        return Err(io::Error::other("launching parent disappeared"));
    }
    Ok(())
}

fn private_dir(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "state directory must be private, owned, and not a symlink",
        ));
    }
    Ok(())
}

fn private_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > MAX_STATE
    {
        return Err(io::Error::other(
            "state file must be private, owned, regular, and bounded",
        ));
    }
    Ok(file)
}

fn read_state(path: &Path) -> Result<Option<State>> {
    let file = match private_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE {
        return Err("state exceeds limit".into());
    }
    let state: State = serde_json::from_slice(&bytes)?;
    if state.version != 1 {
        return Err("unsupported state version".into());
    }
    MachineFile::parse(&state.machine_json)?;
    Ok(Some(state))
}

fn save_state(path: &Path, state: &State) -> Result<()> {
    if path.try_exists()? {
        private_file(path)?;
    }
    let bytes = Zeroizing::new(serde_json::to_vec(state)?);
    if bytes.len() as u64 > MAX_STATE {
        return Err("state exceeds limit".into());
    }
    let temp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    let result = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(
            path.parent()
                .ok_or_else(|| io::Error::other("state has no parent"))?,
        )?
        .sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    Ok(())
}

fn fresh_machine() -> MachineFile {
    let mut host_uuid = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut host_uuid);
    MachineFile {
        host_uuid,
        identity: MachineIdentity {
            device_id: Uuid::new_v4().to_string().to_uppercase(),
            local_user_uuid: Uuid::new_v4().to_string().to_uppercase(),
            client_info: DEFAULT_CLIENT_INFO.into(),
            serial: Some(
                format!("C02{}", &Uuid::new_v4().simple().to_string()[..9]).to_uppercase(),
            ),
            routing: None,
            provisioned_at: None,
        },
        store_export: vec![],
    }
}

fn checkpoint(
    path: &Path,
    state: &mut State,
    machine: &mut MachineFile,
    provider: &CoreAdiAnisette,
) -> Result<()> {
    machine.store_export = provider.export_store()?;
    state.machine_json = machine.to_json();
    save_state(path, state)
}

fn run(args: Args) -> Result<()> {
    protect_process()?;
    if args.host != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err("only IPv4 loopback binding is supported".into());
    }
    private_dir(&args.adi_path)?;
    let directory = args.adi_path.join("macos");
    private_dir(&directory)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("state.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| "another local Mac anisette process owns this profile")?;
    let path = directory.join("machine.json");
    let mut state = match read_state(&path)? {
        Some(state) => state,
        None if args.skip_server_startup => {
            let state = State {
                version: 1,
                phase: Phase::Prepared,
                machine_json: fresh_machine().to_json(),
            };
            save_state(&path, &state)?;
            state
        }
        None => return Err("Mac anisette is not provisioned; run explicit anisette setup".into()),
    };
    if state.phase != Phase::Ready && !args.skip_server_startup {
        return Err(
            "Mac anisette setup was interrupted; resume explicit setup; identity retained".into(),
        );
    }
    let image = fs::read(
        args.coreadi
            .unwrap_or_else(|| args.adi_path.join("lib/CoreADI")),
    )?;
    let mut machine = MachineFile::parse(&state.machine_json)?;
    let provider = Arc::new(
        CoreAdiAnisette::new(&image, &machine, Http::new(Duration::from_secs(30))?)?
            .with_host_locale("UTC", "en_US"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if state.phase == Phase::Prepared {
        // A prior finish may have succeeded before the phase rename. An offline
        // OTP check can recover that case without provisioning again.
        if provider.provider_headers().is_err() {
            let result = runtime.block_on(provision_new_machine(&provider, DS_ID));
            checkpoint(&path, &mut state, &mut machine, &provider)?;
            machine.identity.routing = Some(result?);
        }
        provider.provider_headers()?;
        state.phase = Phase::Ready;
        checkpoint(&path, &mut state, &mut machine, &provider)?;
    }
    if args.skip_server_startup {
        provider.provider_headers()?;
        checkpoint(&path, &mut state, &mut machine, &provider)?;
        return Ok(());
    }
    if args.check_clock {
        let mut first = provider.provider_headers()?;
        let otp = Zeroizing::new(first.remove("X-Apple-I-MD").ok_or("OTP missing")?);
        checkpoint(&path, &mut state, &mut machine, &provider)?;
        std::thread::sleep(Duration::from_secs(31));
        let mut second = provider.provider_headers()?;
        let changed = second
            .remove("X-Apple-I-MD")
            .is_some_and(|value| value != *otp);
        checkpoint(&path, &mut state, &mut machine, &provider)?;
        if !changed {
            return Err("OTP did not change across the clock window".into());
        }
        println!("local OTP changed across the clock window; no network request sent");
        return Ok(());
    }
    let nonce = Zeroizing::new(
        std::env::var("KEYCHAIN_ANISETTE_NONCE")
            .map_err(|_| "managed server mode requires a private per-launch nonce")?,
    );
    if nonce.len() != 64 || !nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid per-launch nonce".into());
    }
    let authorization = Zeroizing::new(format!("Bearer {}", nonce.as_str()));
    let listener = TcpListener::bind((args.host, args.port))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let reply = handle(&mut stream, &runtime, &provider, &authorization);
        // OTP generation can mutate the library's store. Persist before delivery.
        let saved = if reply.is_ok() {
            checkpoint(&path, &mut state, &mut machine, &provider)
        } else {
            Ok(())
        };
        let (code, body) = match (reply, saved) {
            (Ok(body), Ok(())) => (200, body),
            _ => (
                500,
                serde_json::json!({"error":"local anisette operation failed"}),
            ),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&body)?);
        let _ = write!(
            stream,
            "HTTP/1.1 {code} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        let _ = stream.write_all(&bytes);
    }
    Ok(())
}

struct HttpRequest {
    line: String,
    body: Zeroizing<Vec<u8>>,
    authorization: Zeroizing<String>,
}
impl HttpRequest {
    fn authorize(&self, expected: &str) -> Result<()> {
        use subtle::ConstantTimeEq;
        if !bool::from(self.authorization.as_bytes().ct_eq(expected.as_bytes())) {
            return Err("local request authorization failed".into());
        }
        Ok(())
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut header = Zeroizing::new(Vec::new());
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HTTP || Instant::now() >= deadline {
            return Err("HTTP header exceeds bounds".into());
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or("missing request line")?.to_owned();
    let mut length = None;
    let mut authorization = None;
    let mut json = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return Err("duplicate authorization".into());
            }
            authorization = Some(Zeroizing::new(value.trim().to_owned()));
        }
        if name.eq_ignore_ascii_case("content-type") {
            json = value
                .trim()
                .split(';')
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked requests are unsupported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate content length".into());
            }
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = length.unwrap_or(0);
    if request.starts_with("POST ") && !json {
        return Err("JSON content type is required".into());
    }
    if length > MAX_HTTP {
        return Err("HTTP body exceeds bounds".into());
    }
    let mut body = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut body)?;
    Ok(HttpRequest {
        line: request,
        body,
        authorization: authorization.unwrap_or_default(),
    })
}

fn handle(
    stream: &mut TcpStream,
    runtime: &Runtime,
    provider: &CoreAdiAnisette,
    authorization: &str,
) -> Result<serde_json::Value> {
    let request = read_request(stream)?;
    request.authorize(authorization)?;
    match request.line.as_str() {
        "GET / HTTP/1.1" => Ok(serde_json::to_value(provider.provider_headers()?)?),
        "GET /v3/client_info HTTP/1.1" => Ok(serde_json::json!({"client_info":DEFAULT_CLIENT_INFO,
            "user_agent":apple_core::gsa::USER_AGENT,"provider":"macos-coreadi","resync":true})),
        "POST /v1/resync HTTP/1.1" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Resync {
                sim: String,
            }
            let input: Resync = serde_json::from_slice(&request.body)?;
            if input.sim.is_empty() || input.sim.len() > 4096 {
                return Err("resync exceeds bounds".into());
            }
            runtime.block_on(provider.resync(&input.sim))?;
            Ok(serde_json::json!({"resynced":true}))
        }
        _ => Err("unsupported local anisette request".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;
    use std::os::unix::fs::symlink;

    #[test]
    fn private_state_round_trip_rejects_symlinks_permissions_and_corruption() -> Result<()> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("machine.json");
        let state = State {
            version: 1,
            phase: Phase::Prepared,
            machine_json: fresh_machine().to_json(),
        };
        save_state(&path, &state)?;
        let restored = read_state(&path)?.ok_or("missing state")?;
        assert!(restored.phase == Phase::Prepared);
        assert_eq!(restored.machine_json, state.machine_json);
        let link = directory.path().join("link.json");
        symlink(&path, &link)?;
        assert!(read_state(&link).is_err());
        assert!(save_state(&link, &state).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(read_state(&path).is_err());
        assert!(save_state(&path, &state).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, b"invalid")?;
        assert!(read_state(&path).is_err());
        Ok(())
    }

    fn request(bytes: &[u8]) -> Result<HttpRequest> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.write_all(bytes)?;
        client.shutdown(Shutdown::Write)?;
        let (mut server, _) = listener.accept()?;
        read_request(&mut server)
    }

    #[test]
    fn local_http_is_bounded_and_rejects_conflicting_framing() -> Result<()> {
        let parsed =
            request(b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test\r\n\r\n")?;
        assert_eq!(parsed.line, "GET / HTTP/1.1");
        assert_eq!(parsed.authorization.as_str(), "Bearer test");
        assert!(parsed.authorize("Bearer test").is_ok());
        assert!(parsed.authorize("Bearer tesu").is_err());
        assert!(
            request(b"GET / HTTP/1.1\r\n\r\n")?
                .authorize("Bearer test")
                .is_err()
        );
        assert!(parsed.body.is_empty());
        assert!(
            request(b"GET / HTTP/1.1\r\nAuthorization: A\r\nauthorization: B\r\n\r\n").is_err()
        );
        assert!(request(b"POST /v1/resync HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 8193\r\n\r\n").is_err());
        assert!(
            request(b"POST /v1/resync HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 1\r\n\r\n")
                .is_err()
        );
        assert!(
            request(b"POST /v1/resync HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err()
        );
        assert!(request(b"GET / HTTP/1.1\r\nHost: incomplete").is_err());
        Ok(())
    }
}
