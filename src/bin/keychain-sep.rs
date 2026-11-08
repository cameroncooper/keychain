//! Disposable-key diagnostic; not the production broker or browser entry point.
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use keychain::security::authorization::AuthorizationRequirement;
use keychain::security::sep::{NativeSepProvider, StoredSepKey, sign_native};
use keychain_sep_driver::{Device, Guidance};
#[path = "keychain-sep/fprintd.rs"]
mod fprintd;
#[path = "keychain-sep/login.rs"]
mod login;

#[derive(Parser)]
#[command(about = "Diagnose real SEP biometric signing using disposable application keys")]
struct Cli {
    #[arg(long, default_value = "/dev/sep-keys")]
    device: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Opt-in synthetic login/TOTP verification, reveal and single-capture update.
    /// First run may prompt three times; reruns check the same persisted item.
    BrokerLoginCheck {
        #[arg(long)]
        socket: PathBuf,
        /// Private synthetic ciphertext/selection state, retained for reruns.
        #[arg(long)]
        state: PathBuf,
        /// Expect desktop Cancel/Escape, with no touch and no revealed fields.
        #[arg(long)]
        cancel_check: bool,
    },
    /// Hold a real fprintd claim while the broker waits, then release and verify
    /// the disposable migrated credential. Does not enroll or remove prints.
    FprintdCoexistenceCheck {
        record: String,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Exercise real migration using a freshly created synthetic profile only.
    BrokerMigrationCheck {
        #[arg(long)]
        socket: PathBuf,
        /// Must not exist; retained afterwards for fresh-process/reboot checks.
        #[arg(long)]
        profile: PathBuf,
    },
    /// Encrypt a fresh synthetic synced credential for the broker, then verify
    /// it with a fingerprint. Never reads or replaces a real vault credential.
    BrokerImportCheck {
        #[arg(long)]
        socket: PathBuf,
    },
    BrokerVerifyProtected {
        record: String,
        #[arg(long)]
        socket: PathBuf,
    },
    BrokerCancelCheck {
        record: String,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Test desktop cancellation without starting any SEP operation.
    PromptCheck {
        #[arg(long)]
        desktop_owner: u32,
    },
    BrokerStatus {
        #[arg(long, default_value = "/run/keychain/broker.sock")]
        socket: PathBuf,
    },
    BrokerSign {
        record: String,
        message: String,
        #[arg(long, default_value = "/run/keychain/broker.sock")]
        socket: PathBuf,
    },
    Info,
    Create {
        key_file: PathBuf,
        #[arg(long)]
        decrypt: bool,
    },
    /// Round-trip synthetic data through a saved decrypt key, never a real vault.
    DecryptCheck {
        key_file: PathBuf,
        #[arg(long)]
        desktop_owner: Option<u32>,
    },
    Sign {
        key_file: PathBuf,
        /// Diagnostic message (not a private key or password).
        message: String,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=120))]
        timeout: u64,
        /// Cancel this diagnostic request without supplying a fingerprint.
        #[arg(long)]
        cancel_after_ms: Option<u64>,
        /// Present the diagnostic's fingerprint prompt in this user's desktop.
        #[arg(long)]
        desktop_owner: Option<u32>,
    },
}
fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("keychain-sep: {error}");
        std::process::exit(1);
    }
}
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::BrokerLoginCheck {
            socket,
            state,
            cancel_check,
        } => login::check(&socket, &state, cancel_check)?,
        Command::FprintdCoexistenceCheck { record, socket } => fprintd::check(record, socket)?,
        Command::BrokerMigrationCheck { socket, profile } => {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            use keychain::model::{PasskeyCredential, PasskeyProvenance, VaultState};
            use keychain::security::{KeyUsage, SecurityBackend, SoftwareFileBackend};
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use std::os::unix::fs::DirBuilderExt;
            keychain_sep_driver::memory::make_process_nondumpable()?;
            std::fs::DirBuilder::new().mode(0o700).create(&profile)?;
            let paths = keychain::paths::AppPaths::new(
                profile.join("config/keychain"),
                profile.join("state/keychain"),
                profile.join("runtime/keychain"),
            )?;
            let backend = SoftwareFileBackend::new(paths.clone());
            let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let mut x963 = zeroize::Zeroizing::new(
                key.public_key().to_encoded_point(false).as_bytes().to_vec(),
            );
            x963.extend_from_slice(&key.to_bytes());
            drop(key);
            let source = backend.import_p256_x963(KeyUsage::WebAuthnSigning, &x963)?;
            drop(x963);
            let id = uuid::Uuid::new_v4().to_string();
            let credential = PasskeyCredential {
                id: id.clone(),
                rp_id: "diagnostic.invalid".into(),
                provenance: PasskeyProvenance::Synced,
                credential_id: URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
                user_handle: URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
                username: "Synthetic migration check".into(),
                display_name: "Synthetic migration check".into(),
                created_at: 0.0,
                modified_at: 0.0,
                signing_key: source.clone(),
            };
            let store = keychain::store::StateStore::new(&paths, &backend);
            store.save_vault(&VaultState {
                schema_version: 1,
                synced_at: 0,
                credentials: vec![],
                passkeys: vec![credential],
            })?;
            println!("synthetic profile: {}", profile.display());
            println!("synthetic record: {id}");
            let _lock = keychain::paths::StateLock::acquire(&paths)?;
            let outcome =
                keychain::protection::migrate_passkey(&paths, &backend, &store, &id, &socket)?;
            if !outcome.source_retained || backend.public_x963(&source).is_err() {
                return Err("migration lost its synthetic recovery copy".into());
            }
            println!(
                "verified synthetic migration revision {}; source retained; broker-only reference committed",
                outcome.revision
            );
        }
        Command::BrokerVerifyProtected { record, socket } => {
            println!(
                "{}",
                keychain::broker::call(
                    &socket,
                    keychain::broker::Operation::VerifyProtected { record }
                )?
            );
        }
        Command::BrokerImportCheck { socket } => {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            use keychain::broker::{
                Operation,
                registry::{ProtectedImport, Recipient},
            };
            use keychain::model::{PasskeyCredential, PasskeyProvenance};
            use keychain::security::{KeyAlgorithm, KeyRef, KeyUsage};
            keychain_sep_driver::memory::make_process_nondumpable()?;
            let recipient: Recipient =
                serde_json::from_value(keychain::broker::call(&socket, Operation::ItemRecipient)?)?;
            let id = uuid::Uuid::new_v4().to_string();
            let credential = PasskeyCredential {
                id: id.clone(),
                rp_id: "diagnostic.invalid".into(),
                provenance: PasskeyProvenance::Synced,
                credential_id: URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
                user_handle: URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
                username: "Disposable synced passkey".into(),
                display_name: "Disposable synced passkey".into(),
                created_at: 0.0,
                modified_at: 0.0,
                signing_key: KeyRef {
                    backend_id: "sep-protected-software-v1".into(),
                    key_id: id.clone(),
                    usage: KeyUsage::WebAuthnSigning,
                    algorithm: KeyAlgorithm::P256,
                },
            };
            let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let scalar = zeroize::Zeroizing::new(key.to_bytes());
            drop(key);
            let import = ProtectedImport::seal_scalar(
                keychain_sep_driver::peer::effective_uid(),
                &recipient,
                0,
                credential,
                &scalar,
                true,
            )?;
            drop(scalar);
            println!("synthetic record: {id}");
            keychain::broker::call(
                &socket,
                Operation::ImportProtected {
                    import: Box::new(import),
                },
            )?;
            println!(
                "{}",
                keychain::broker::call(&socket, Operation::VerifyProtected { record: id })?
            );
        }
        Command::BrokerCancelCheck { record, socket } => {
            match keychain::broker::call(
                &socket,
                keychain::broker::Operation::DiagnosticCancelTest { record },
            ) {
                Err(keychain::Error::Sep(keychain::security::sep::ProviderError::Canceled)) => {
                    println!(
                        "verified desktop cancellation of the pending SEP operation; no signature delivered"
                    )
                }
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("cancellation test unexpectedly succeeded".into()),
            }
        }
        Command::PromptCheck { desktop_owner } => {
            if desktop_owner == 0 {
                return Err("desktop owner must be unprivileged".into());
            }
            let path = PathBuf::from(format!("/run/user/{desktop_owner}/keychain-auth.sock"));
            let mut prompt = keychain::prompt::PromptSession::connect(
                &path,
                desktop_owner,
                keychain::prompt::Presentation::diagnostic(
                    uuid::Uuid::new_v4(),
                    keychain::prompt::PromptOperation::DiagnosticCancel,
                    "No fingerprint or SEP operation will run",
                ),
            )?;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            prompt.set_deadline(Some(deadline))?;
            prompt.status(
                keychain::prompt::PromptPhase::DiagnosticCancel,
                "Click Cancel or press Escape — do not touch the reader",
            )?;
            while !prompt.canceled() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
            if !prompt.canceled() {
                return Err("prompt check expired without cancellation".into());
            }
            println!("verified desktop cancellation; no SEP operation was started");
        }
        Command::BrokerStatus { socket } => {
            println!(
                "{}",
                keychain::broker::call(&socket, keychain::broker::Operation::Status)?
            );
        }
        Command::BrokerSign {
            socket,
            record,
            message,
        } => {
            println!(
                "{}",
                keychain::broker::call(
                    &socket,
                    keychain::broker::Operation::DiagnosticSign { record, message }
                )?
            );
        }
        Command::Info => {
            let device = Device::open(&cli.device)?;
            let info = device.info();
            println!(
                "key API version: {}; signing: {}; decryption: {} (not a sensor health check)",
                info.version,
                info.signing(),
                info.decryption()
            );
        }
        Command::Create { key_file, decrypt } => {
            if key_file.try_exists()? {
                return Err("key file already exists".into());
            }
            let mut device = Device::open(&cli.device)?;
            let key = StoredSepKey::create_for_policy(&mut device, decrypt)?;
            key.save_new(&key_file)?;
            println!(
                "created biometric application key {}",
                key.reference().key_id
            );
        }
        Command::DecryptCheck {
            key_file,
            desktop_owner,
        } => {
            use keychain::security::sep::envelope::{item_view, seal_item};
            use keychain_sep_driver::memory::{SecretBuffer, make_process_nondumpable};
            make_process_nondumpable()?;
            let key = StoredSepKey::load(&key_file)?;
            let context =
                b"keychain-disposable-test:owner=diagnostic;record=1;purpose=synthetic;v=1";
            let sealed = seal_item(&key.public_sec1()?, context, b"synthetic SEP item check")?;
            let mut output = SecretBuffer::new()?;
            let mut prompt = if let Some(owner) = desktop_owner {
                if owner == 0 {
                    return Err("desktop owner must be unprivileged".into());
                }
                let path = PathBuf::from(format!("/run/user/{owner}/keychain-auth.sock"));
                Some(keychain::prompt::PromptSession::connect(
                    &path,
                    owner,
                    keychain::prompt::Presentation::diagnostic(
                        uuid::Uuid::new_v4(),
                        keychain::prompt::PromptOperation::DiagnosticDecrypt,
                        "Saved SEP item recipient",
                    ),
                )?)
            } else {
                None
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            if let Some(prompt) = &mut prompt {
                prompt.set_deadline(Some(deadline))?;
            }
            let mut device = Device::open(&cli.device)?;
            eprintln!("Synthetic decrypt check: touch an enrolled finger to the reader");
            let size = key.decrypt_into(
                &mut device,
                &sealed,
                output.as_mut_array(),
                deadline.saturating_duration_since(std::time::Instant::now()),
                |guidance| {
                    let Some(prompt) = &mut prompt else {
                        return true;
                    };
                    if std::time::Instant::now() >= deadline || prompt.canceled() {
                        return false;
                    }
                    prompt
                        .status(
                            guidance.into(),
                            match guidance {
                                Guidance::WaitingForDevice => "Waiting for the fingerprint reader…",
                                Guidance::Preparing => "Preparing fingerprint reader…",
                                Guidance::PlaceFinger => "Touch the fingerprint reader",
                            },
                        )
                        .is_ok()
                },
            )?;
            if std::time::Instant::now() >= deadline
                || prompt.as_ref().is_some_and(|prompt| prompt.canceled())
            {
                return Err(keychain::security::sep::ProviderError::Canceled.into());
            }
            let item = item_view(output.as_array(), size, context)?;
            if item != b"synthetic SEP item check" {
                return Err("synthetic item mismatch".into());
            }
            if item_view(output.as_array(), size, b"wrong selected record").is_ok() {
                return Err("binding check failed".into());
            }
            println!(
                "verified biometric item decryption and context binding; {} byte locked/dump-excluded mapping",
                output.mapping_len()
            );
        }
        Command::Sign {
            key_file,
            message,
            timeout,
            cancel_after_ms,
            desktop_owner,
        } => {
            let key = StoredSepKey::load(&key_file)?;
            let prompt = if let Some(owner) = desktop_owner {
                if owner == 0 {
                    return Err("desktop owner must be unprivileged".into());
                }
                let path = PathBuf::from(format!("/run/user/{owner}/keychain-auth.sock"));
                Some(std::sync::Arc::new(std::sync::Mutex::new(
                    keychain::prompt::PromptSession::connect(
                        &path,
                        owner,
                        keychain::prompt::Presentation::diagnostic(
                            uuid::Uuid::new_v4(),
                            keychain::prompt::PromptOperation::DiagnosticSign,
                            "Disposable SEP key",
                        ),
                    )?,
                )))
            } else {
                None
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
            if let Some(prompt) = &prompt {
                prompt
                    .lock()
                    .map_err(|_| "prompt connection failed")?
                    .set_deadline(Some(deadline))?;
            }
            let display = prompt.clone();
            let last = std::sync::Mutex::new(None);
            let started = std::time::Instant::now();
            let provider = NativeSepProvider::new(key, cli.device, move |guidance| {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                if let Some(display) = &display {
                    let Ok(mut session) = display.lock() else {
                        return false;
                    };
                    if session.canceled() {
                        return false;
                    }
                    let text = match guidance {
                        Guidance::WaitingForDevice => "Waiting for the fingerprint reader…",
                        Guidance::Preparing => "Preparing fingerprint reader…",
                        Guidance::PlaceFinger => "Touch the fingerprint reader",
                    };
                    if session.status(guidance.into(), text).is_err() {
                        return false;
                    }
                }
                if cancel_after_ms
                    .is_some_and(|limit| started.elapsed() >= Duration::from_millis(limit))
                {
                    return false;
                }
                let Ok(mut previous) = last.lock() else {
                    return false;
                };
                if *previous == Some(guidance) {
                    return true;
                }
                *previous = Some(guidance);
                if guidance == Guidance::PlaceFinger {
                    eprintln!("Touch an enrolled finger to the reader");
                }
                true
            })?;
            eprintln!("Preparing biometric signing…");
            let outcome = sign_native(
                &provider,
                provider.reference(),
                &provider.public_sec1()?,
                message.as_bytes(),
                deadline.saturating_duration_since(std::time::Instant::now()),
            )?;
            let signature = outcome.into_signature(
                provider.reference(),
                message.as_bytes(),
                AuthorizationRequirement::UserVerification,
            )?;
            if let Some(prompt) = &prompt {
                let session = prompt.lock().map_err(|_| "prompt connection failed")?;
                if session.canceled() {
                    return Err("biometric operation canceled".into());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("biometric operation expired".into());
            }
            println!(
                "verified native biometric signature: {}",
                hex::encode(signature)
            );
        }
    }
    Ok(())
}
