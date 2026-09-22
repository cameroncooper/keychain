use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use keychain::apple::anisette::{ManagedAnisette, validate_helper};
use keychain::apple::{anisette, auth, cloudkit, escrow, octagon};
use keychain::config::Config;
use keychain::credential;
use keychain::model::{
    AccountState, Credential, DeviceIdentity, OctagonState, OctagonTrustState, VaultState,
};
use keychain::paths::{AppPaths, StateLock};
use keychain::security::{SecurityBackend, SoftwareFileBackend};
use keychain::store::StateStore;
use keychain::{Error, Result};
use plist::{Dictionary, Value};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "keychain",
    version,
    about = "Read-only Apple Passwords client for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Configure or inspect the on-demand anisette helper.
    Anisette {
        #[command(subcommand)]
        command: AnisetteCommand,
    },
    /// Authenticate and join Octagon in one guarded first-run flow.
    Setup {
        #[arg(long)]
        username: Option<String>,
        /// Select this escrow record without prompting.
        #[arg(long, value_name = "RECORD_LABEL")]
        bottle: Option<String>,
    },
    /// Authenticate this device with Apple. The password is never saved.
    Login {
        #[arg(long)]
        username: Option<String>,
    },
    /// List recoverable escrow bottles without spending an attempt.
    Bottles,
    /// Join Octagon trust through explicitly confirmed escrow recovery.
    Join {
        /// Select this escrow record without prompting.
        #[arg(long, value_name = "RECORD_LABEL")]
        bottle: Option<String>,
    },
    /// Download and decrypt the latest password snapshot.
    Sync,
    /// List locally cached credentials without revealing passwords.
    List { query: Option<String> },
    /// Reveal one locally cached credential.
    Show { id: String },
    /// Generate the current verification code for one credential.
    Totp { id: String },
    /// Show local authentication and vault status.
    Status,
    /// Remove local account, trust, and vault state.
    Logout {
        /// Also remove the stable Apple-facing identity and anisette machine data.
        #[arg(long)]
        forget_device: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AnisetteCommand {
    /// Provision the external helper and remember its absolute path.
    Setup {
        #[arg(long)]
        helper: PathBuf,
    },
    Status,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("keychain: {error}");
        std::process::exit(exit_code(&error));
    }
}

fn run(cli: Cli) -> Result<()> {
    let paths = AppPaths::discover()?;
    let config = Config::load(&paths)?;
    let backend = SoftwareFileBackend::new(paths.clone());
    let store = StateStore::new(&paths, &backend);
    match cli.command {
        Command::Anisette { command } => command_anisette(command, &paths, config),
        Command::Setup { username, bottle } => {
            let _lock = StateLock::acquire(&paths)?;
            command_setup(
                username,
                bottle.as_deref(),
                &paths,
                config,
                &backend,
                &store,
            )
        }
        Command::Login { username } => {
            let _lock = StateLock::acquire(&paths)?;
            command_login(username, &paths, config, &backend, &store)
        }
        Command::Bottles => {
            let _lock = StateLock::acquire(&paths)?;
            command_bottles(&paths, config, &backend, &store)
        }
        Command::Join { bottle } => {
            let _lock = StateLock::acquire(&paths)?;
            command_join(bottle.as_deref(), &paths, config, &backend, &store)
        }
        Command::Sync => {
            let _lock = StateLock::acquire(&paths)?;
            command_sync(&paths, config, &backend, &store)
        }
        Command::List { query } => command_list(query.as_deref(), &store),
        Command::Show { id } => command_show(&id, &store),
        Command::Totp { id } => command_totp(&id, &store),
        Command::Status => command_status(&paths, &config, &backend, &store),
        Command::Logout { forget_device } => {
            let _lock = StateLock::acquire(&paths)?;
            command_logout(forget_device, &paths, &backend, &store)
        }
    }
}

fn command_anisette(command: AnisetteCommand, paths: &AppPaths, mut config: Config) -> Result<()> {
    match command {
        AnisetteCommand::Setup { helper } => {
            let _lock = StateLock::acquire(paths)?;
            let helper = validate_helper(&helper)?;
            eprintln!(
                "Provisioning anisette machine data with {}…",
                helper.display()
            );
            anisette::setup(&helper, paths)?;
            config.anisette_helper = Some(helper.clone());
            config.save(paths)?;
            println!("configured {}", helper.display());
            Ok(())
        }
        AnisetteCommand::Status => {
            let Some(helper) = &config.anisette_helper else {
                println!("not configured");
                return Ok(());
            };
            let path = validate_helper(helper)?;
            println!("helper: {}", path.display());
            println!(
                "machine data: {}",
                if paths.anisette_dir().exists() {
                    "present"
                } else {
                    "missing; run anisette setup"
                }
            );
            println!("lifecycle: launched only for network commands");
            Ok(())
        }
    }
}

fn command_setup(
    requested_username: Option<String>,
    requested_label: Option<&str>,
    paths: &AppPaths,
    config: Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let anisette = ManagedAnisette::start(require_helper(&config)?, paths)?;
    let (account, device, state, escrow_pet) =
        authenticate_and_prepare(requested_username, &anisette, backend, store)?;
    println!("signed in as {}", account.username);
    if matches!(state.trust_state, OctagonTrustState::Joined) {
        println!("Octagon: already joined as {}", state.peer_id);
        return Ok(());
    }
    eprintln!("Continuing with guarded Octagon recovery…");
    join_octagon(
        requested_label,
        &account,
        &device,
        &anisette,
        backend,
        store,
        state,
        Some(escrow_pet),
    )
}

fn command_login(
    requested_username: Option<String>,
    paths: &AppPaths,
    config: Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let anisette = ManagedAnisette::start(require_helper(&config)?, paths)?;
    let (account, _device, octagon, mut pet) =
        authenticate_and_prepare(requested_username, &anisette, backend, store)?;
    pet.zeroize();
    println!("signed in as {}", account.username);
    println!(
        "Octagon: {}",
        if octagon.trust_state.is_joined() {
            "joined"
        } else {
            "identity ready; run `keychain join`"
        }
    );
    Ok(())
}

fn authenticate_and_prepare(
    requested_username: Option<String>,
    anisette: &dyn anisette::AnisetteProvider,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<(
    AccountState,
    DeviceIdentity,
    OctagonState,
    Zeroizing<String>,
)> {
    let prior_account = store.load_account()?;
    let default_username = prior_account
        .as_ref()
        .map(|account| account.username.as_str());
    let username = match requested_username {
        Some(username) if !username.trim().is_empty() => username.trim().to_owned(),
        _ => prompt_line(match default_username {
            Some(username) => format!("Apple ID [{username}]: "),
            None => "Apple ID: ".into(),
        })?
        .trim()
        .to_owned(),
    };
    let username = if username.is_empty() {
        default_username
            .map(str::to_owned)
            .ok_or_else(|| Error::Config("no Apple ID was provided".into()))?
    } else {
        username
    };
    let mut password = Zeroizing::new(read_secret("Apple ID password: ")?);
    if password.is_empty() {
        return Err(Error::Refused("empty Apple ID password".into()));
    }
    let device =
        auth::load_or_create_device(store.load_device()?, |device| store.save_device(device))?;
    eprintln!("Signing in to Apple…");
    let auth::AccountLogin { mut account, pet } =
        auth::login_account_with_pet(&username, &password, &device, anisette, prompt_two_factor)?;
    password.zeroize();
    cloudkit::ensure_cloudkit_user_id(&mut account, anisette)?;
    let (octagon, created) =
        octagon::ensure_peer_identity(store.load_octagon()?, &account, &device, backend)?;
    store.save_account(&account)?;
    if created {
        store.save_octagon(&octagon)?;
    }
    Ok((account, device, octagon, pet))
}

fn command_bottles(
    paths: &AppPaths,
    config: Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let anisette = ManagedAnisette::start(require_helper(&config)?, paths)?;
    let mut account = require_account(store)?;
    let device = require_device(store)?;
    if cloudkit::ensure_cloudkit_user_id(&mut account, &anisette)? {
        store.save_account(&account)?;
    }
    let octagon = require_octagon(store)?;
    validate_account_binding(&account, &octagon)?;
    let client = octagon::OctagonClient::new(&account, &device, &anisette, backend)?;
    let bottles = client.fetch_viable_bottles()?;
    if bottles.is_empty() {
        println!("no viable escrow bottles");
        return Ok(());
    }
    let metadata = match escrow_host(&account) {
        Ok(host) => {
            eprintln!("A fresh Apple sign-in is needed only to read escrow device metadata.");
            let mut password = Zeroizing::new(read_secret("Apple ID password: ")?);
            let mut pet = auth::mint_pet(
                &account.username,
                &password,
                &device,
                &anisette,
                prompt_two_factor,
            )?;
            password.zeroize();
            let metadata = escrow::EscrowRecovery::new(host, &account.username, &pet, &anisette)
                .and_then(|recovery| recovery.list_records())
                .map(|records| {
                    records
                        .into_iter()
                        .map(|record| (record.label, record.metadata))
                        .collect::<BTreeMap<_, _>>()
                });
            pet.zeroize();
            metadata
        }
        Err(error) => Err(error),
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("warning: escrow device metadata unavailable: {error}");
            BTreeMap::new()
        }
    };
    for bottle in bottles {
        let description = metadata
            .get(&bottle.record_label)
            .map(describe_metadata)
            .unwrap_or_else(|| "unknown device".into());
        println!("{}\t{}", bottle.record_label, description);
    }
    Ok(())
}

fn command_join(
    requested_label: Option<&str>,
    paths: &AppPaths,
    config: Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let anisette = ManagedAnisette::start(require_helper(&config)?, paths)?;
    let mut account = require_account(store)?;
    let device = require_device(store)?;
    if cloudkit::ensure_cloudkit_user_id(&mut account, &anisette)? {
        store.save_account(&account)?;
    }
    let state = require_octagon(store)?;
    validate_account_binding(&account, &state)?;
    join_octagon(
        requested_label,
        &account,
        &device,
        &anisette,
        backend,
        store,
        state,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn join_octagon(
    requested_label: Option<&str>,
    account: &AccountState,
    device: &DeviceIdentity,
    anisette: &dyn anisette::AnisetteProvider,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    mut state: OctagonState,
    escrow_pet: Option<Zeroizing<String>>,
) -> Result<()> {
    let client = octagon::OctagonClient::new(account, device, anisette, backend)?;
    if matches!(state.trust_state, OctagonTrustState::Joined) {
        println!("already joined as {}", state.peer_id);
        return Ok(());
    }
    if let Some(escrow_record_label) = state.trust_state.escrow_record_label() {
        if let Some(requested_label) = requested_label {
            if escrow_record_label != requested_label {
                return Err(Error::Refused(format!(
                    "an interrupted join for bottle {} is already stored; resume that bottle or log out before selecting another",
                    escrow_record_label
                )));
            }
        }
        match &state.trust_state {
            OctagonTrustState::SponsorRecovered { .. } => eprintln!(
                "Resuming with the already recovered sponsor; no escrow attempt will be spent."
            ),
            OctagonTrustState::JoinedAwaitingTlkVerification { .. } => eprintln!(
                "Creating and verifying self-addressed TLKShares so the recovered sponsor key can be retired."
            ),
            OctagonTrustState::JoinedSponsorRetirementVerified { .. } => {
                eprintln!("Completing verified recovery-sponsor key retirement.")
            }
            OctagonTrustState::IdentityReady | OctagonTrustState::Joined => {
                unreachable!("a sponsor phase has an escrow record label")
            }
        }
        return finish_sponsor_join(&client, store, &mut state);
    }

    let viable_bottles = client.fetch_viable_bottles()?;
    if viable_bottles.is_empty() {
        return Err(Error::Config(
            "no viable escrow bottles are available for this account".into(),
        ));
    }
    let requested_index = requested_label
        .map(|label| {
            viable_bottles
                .iter()
                .position(|bottle| bottle.record_label == label)
                .ok_or_else(|| Error::Config(format!("no viable bottle named {label}")))
        })
        .transpose()?;
    let host = escrow_host(account)?;
    let mut escrow_pet = match escrow_pet {
        Some(pet) => pet,
        None => {
            let mut password = Zeroizing::new(read_secret("Apple ID password: ")?);
            let pet = auth::mint_pet(
                &account.username,
                &password,
                device,
                anisette,
                prompt_two_factor,
            )?;
            password.zeroize();
            pet
        }
    };
    let metadata = match escrow::EscrowRecovery::new(host, &account.username, &escrow_pet, anisette)
        .and_then(|recovery| recovery.list_records())
    {
        Ok(records) => records
            .into_iter()
            .map(|record| (record.label, record.metadata))
            .collect::<BTreeMap<_, _>>(),
        Err(error) => {
            eprintln!("warning: escrow device metadata unavailable: {error}");
            BTreeMap::new()
        }
    };

    let selected_index = match requested_index {
        Some(index) => index,
        None => prompt_bottle_choice(&viable_bottles, &metadata)?,
    };
    let viable = &viable_bottles[selected_index];
    let record_label = viable.record_label.clone();
    let bottle = client.decode_bottle(viable)?;
    let selected_metadata = metadata.get(&record_label);

    println!("selected bottle: {record_label}");
    println!(
        "device: {}",
        selected_metadata
            .map(describe_metadata)
            .unwrap_or_else(|| "unknown device".into())
    );
    eprintln!("WARNING: A wrong device passcode spends one of 10 server-enforced escrow attempts.");
    eprintln!("The tenth failed attempt can destroy this escrow recovery record permanently.");
    let confirmation = prompt_line("Proceed with escrow recovery? (y/N): ")?;
    if !confirmation.trim().eq_ignore_ascii_case("y") {
        return Err(Error::Refused(
            "recovery cancelled; no escrow attempt was spent".into(),
        ));
    }
    let mut passcode = Zeroizing::new(
        read_secret("Passcode / iCloud Security Code for the selected device: ")?.into_bytes(),
    );
    if passcode.is_empty() {
        return Err(Error::Refused(
            "empty passcode; no escrow attempt was spent".into(),
        ));
    }
    // The short-lived PET is reusable within this join. Avoid a second back-to-back GSA login:
    // GETRECORDS and the immediately following SRP recovery share the same escrow authorization.
    let recovery = escrow::EscrowRecovery::new(host, &account.username, &escrow_pet, anisette)?;
    let entropy = recovery.recover_entropy(&record_label, &passcode, true)?;
    drop(recovery);
    escrow_pet.zeroize();
    passcode.zeroize();
    let identity = escrow::recover_identity(backend, &bottle, &entropy, &account.adsid)?;
    octagon::set_recovered_sponsor(&mut state, &record_label, identity);
    // Persist before a network join so interruption never causes another automatic recovery.
    store.save_octagon(&state)?;
    finish_sponsor_join(&client, store, &mut state)
}

fn finish_sponsor_join(
    client: &octagon::OctagonClient<'_>,
    store: &StateStore<'_>,
    state: &mut OctagonState,
) -> Result<()> {
    let outcome = client.join_with_sponsor(state)?;
    // This checkpoint makes retirement crash-safe: after successful verification, a restart can
    // delete the old key without needing it to decrypt the sponsor shares again.
    store.save_octagon(state)?;
    let (uploaded_tlk_shares, awaiting_reason) = match outcome {
        octagon::JoinOutcome::SponsorRetirementReady {
            uploaded_tlk_shares,
        } => {
            client.retire_verified_sponsor(state)?;
            store.save_octagon(state)?;
            (uploaded_tlk_shares, None)
        }
        octagon::JoinOutcome::AwaitingSelfShareVerification {
            uploaded_tlk_shares,
            reason,
        } => (uploaded_tlk_shares, Some(reason)),
    };
    println!("joined Octagon as {}", state.peer_id);
    if uploaded_tlk_shares > 0 {
        println!(
            "uploaded {} self-addressed TLK share(s)",
            uploaded_tlk_shares
        );
    }
    if awaiting_reason.is_none() {
        println!("verified self recovery; retired the recovered sponsor key");
    }
    if let Some(reason) = awaiting_reason {
        eprintln!("warning: {reason}");
    }
    Ok(())
}

fn command_sync(
    paths: &AppPaths,
    config: Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let anisette = ManagedAnisette::start(require_helper(&config)?, paths)?;
    let mut account = require_account(store)?;
    let device = require_device(store)?;
    auth::refresh_account_settings(&mut account, &device, &anisette)?;
    cloudkit::ensure_cloudkit_user_id(&mut account, &anisette)?;
    store.save_account(&account)?;
    let state = require_octagon(store)?;
    validate_account_binding(&account, &state)?;
    let client = octagon::OctagonClient::new(&account, &device, &anisette, backend)?;
    eprintln!("Fetching and decrypting Passwords and Manatee zones…");
    let projection = client.sync_credentials(&state)?;
    let count = projection.credentials.len();
    let ignored_passkeys = projection.ignored_passkeys;
    store.save_vault(&VaultState {
        schema_version: 1,
        synced_at: unix_now(),
        credentials: projection.credentials,
    })?;
    println!("synced {count} credential(s)");
    if ignored_passkeys > 0 {
        println!("ignored {ignored_passkeys} passkey record(s): passkeys are not supported");
    }
    Ok(())
}

fn command_list(query: Option<&str>, store: &StateStore<'_>) -> Result<()> {
    let vault = require_vault(store)?;
    for item in credential::search(&vault.credentials, query.unwrap_or_default()) {
        println!(
            "{}\t{}\t{}\t{}",
            short_id(&item.id),
            credential::printable(&item.domain),
            credential::printable(&item.username),
            credential::printable(&item.title)
        );
    }
    Ok(())
}

fn command_show(id: &str, store: &StateStore<'_>) -> Result<()> {
    let vault = require_vault(store)?;
    let item = find_credential(&vault.credentials, id)?;
    println!("id: {}", item.id);
    println!("title: {}", credential::printable(&item.title));
    println!("domain: {}", credential::printable(&item.domain));
    println!("username: {}", credential::printable(&item.username));
    println!("password: {}", item.password);
    if !item.notes.is_empty() {
        println!("notes: {}", credential::printable(&item.notes));
    }
    if !item.totp_uri.is_empty() {
        println!("totp: configured");
    }
    Ok(())
}

fn command_totp(id: &str, store: &StateStore<'_>) -> Result<()> {
    let vault = require_vault(store)?;
    let item = find_credential(&vault.credentials, id)?;
    let code = keychain::totp::generate(&item.totp_uri, unix_now() as u64)
        .ok_or_else(|| Error::InvalidData("credential has no usable TOTP configuration".into()))?;
    println!("{}", code.code);
    Ok(())
}

fn command_status(
    paths: &AppPaths,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    println!(
        "anisette: {}",
        config
            .anisette_helper
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not configured".into())
    );
    println!("security backend: {}", backend.backend_id());
    println!(
        "software key: {}",
        if paths.software_key_file().exists() {
            "present (mode-0600 root key)"
        } else {
            "not created"
        }
    );
    match store.load_account()? {
        Some(account) => {
            println!("account: {}", account.username);
            println!("signed in: {}", account.logged_in_at);
            println!("service URLs: {}", account.webservices.len());
        }
        None => println!("account: not signed in"),
    }
    match store.load_octagon()? {
        Some(octagon) => {
            println!("Octagon peer: {}", octagon.peer_id);
            println!("Octagon joined: {}", octagon.trust_state.is_joined());
            match &octagon.trust_state {
                OctagonTrustState::SponsorRecovered { peer_id, .. } => {
                    println!("recovery sponsor: {peer_id} (recovered; join pending)")
                }
                OctagonTrustState::JoinedAwaitingTlkVerification {
                    sponsor_peer_id, ..
                } => println!(
                    "recovery sponsor: {sponsor_peer_id} (encryption key retained until self recovery is verified)"
                ),
                OctagonTrustState::JoinedSponsorRetirementVerified {
                    sponsor_peer_id, ..
                } => println!(
                    "recovery sponsor: {sponsor_peer_id} (self recovery verified; retirement pending)"
                ),
                OctagonTrustState::IdentityReady | OctagonTrustState::Joined => {
                    println!("recovery sponsor: none")
                }
            }
        }
        None => println!("Octagon peer: none"),
    }
    match store.load_vault()? {
        Some(vault) => {
            println!("vault entries: {}", vault.credentials.len());
            println!("last sync: {}", vault.synced_at);
        }
        None => println!("vault: empty"),
    }
    Ok(())
}

fn command_logout(
    forget_device: bool,
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    match store.load_octagon() {
        Ok(Some(octagon)) => destroy_octagon_keys(backend, &octagon),
        Ok(None) => {}
        Err(error) if forget_device => {
            eprintln!(
                "warning: Octagon state could not be decoded ({error}); performing the requested full local reset"
            );
        }
        Err(error) => return Err(error),
    }
    for path in [
        paths.account_file(),
        paths.octagon_file(),
        paths.vault_file(),
    ] {
        store.remove_if_exists(&path)?;
    }
    if forget_device {
        for path in [
            paths.device_file(),
            paths.keys_file(),
            paths.software_key_file(),
        ] {
            store.remove_if_exists(&path)?;
        }
        if paths.anisette_dir().exists() {
            std::fs::remove_dir_all(paths.anisette_dir())
                .map_err(|error| Error::io(paths.anisette_dir(), error))?;
        }
    }
    println!(
        "removed local account, Octagon, and vault state{}",
        if forget_device {
            "; also removed device, anisette machine data, and the software security root"
        } else {
            ""
        }
    );
    Ok(())
}

fn destroy_octagon_keys(backend: &dyn SecurityBackend, state: &OctagonState) {
    let _ = backend.destroy_key(&state.signing_key);
    let _ = backend.destroy_key(&state.encryption_key);
    match &state.trust_state {
        OctagonTrustState::SponsorRecovered {
            signing_key,
            encryption_key,
            ..
        } => {
            let _ = backend.destroy_key(signing_key);
            let _ = backend.destroy_key(encryption_key);
        }
        OctagonTrustState::JoinedAwaitingTlkVerification {
            sponsor_encryption_key,
            ..
        }
        | OctagonTrustState::JoinedSponsorRetirementVerified {
            sponsor_encryption_key,
            ..
        } => {
            let _ = backend.destroy_key(sponsor_encryption_key);
        }
        OctagonTrustState::IdentityReady | OctagonTrustState::Joined => {}
    }
}

fn require_helper(config: &Config) -> Result<&std::path::Path> {
    config.anisette_helper.as_deref().ok_or_else(|| {
        Error::Config("anisette is not configured; run `keychain anisette setup --helper /absolute/path/to/anisette-v3-server`".into())
    })
}

fn require_account(store: &StateStore<'_>) -> Result<AccountState> {
    store
        .load_account()?
        .ok_or_else(|| Error::AuthenticationRequired("not signed in; run `keychain login`".into()))
}

fn require_device(store: &StateStore<'_>) -> Result<DeviceIdentity> {
    store.load_device()?.ok_or_else(|| {
        Error::AuthenticationRequired("no stable device identity; run `keychain login`".into())
    })
}

fn require_octagon(store: &StateStore<'_>) -> Result<OctagonState> {
    store
        .load_octagon()?
        .ok_or_else(|| Error::Config("no Octagon identity; run `keychain login`".into()))
}

fn require_vault(store: &StateStore<'_>) -> Result<VaultState> {
    store
        .load_vault()?
        .ok_or_else(|| Error::Config("vault is empty; run `keychain sync`".into()))
}

fn validate_account_binding(account: &AccountState, octagon: &OctagonState) -> Result<()> {
    if octagon.account_fingerprint != octagon::account_fingerprint(account) {
        return Err(Error::Security(
            "account and Octagon identity do not belong together".into(),
        ));
    }
    Ok(())
}

fn escrow_host(account: &AccountState) -> Result<&str> {
    ["keychainsync", "escrowproxy"]
        .iter()
        .find_map(|name| account.webservices.get(*name))
        .map(String::as_str)
        .or_else(|| {
            account
                .webservices
                .iter()
                .find(|(name, _)| name.to_ascii_lowercase().contains("keychainsync"))
                .map(|(_, url)| url.as_str())
        })
        .ok_or_else(|| Error::Config("account settings contain no keychainsync escrow URL".into()))
}

fn describe_metadata(metadata: &Dictionary) -> String {
    let client = metadata
        .get("ClientMetadata")
        .and_then(Value::as_dictionary);
    let first = |dictionary: &Dictionary, names: &[&str]| {
        names.iter().find_map(|name| match dictionary.get(name) {
            Some(Value::String(value)) => Some(value.clone()),
            Some(Value::Integer(value)) => Some(value.to_string()),
            _ => None,
        })
    };
    let name = client
        .and_then(|client| {
            first(
                client,
                &[
                    "device_model",
                    "model",
                    "ProductType",
                    "device_name",
                    "deviceName",
                ],
            )
        })
        .unwrap_or_else(|| "unknown device".into());
    let serial = first(metadata, &["serial"]).unwrap_or_else(|| "unknown serial".into());
    format!("{name} ({serial})")
}

fn prompt_bottle_choice(
    bottles: &[octagon::ViableBottle],
    metadata: &BTreeMap<String, Dictionary>,
) -> Result<usize> {
    if bottles.len() == 1 {
        let bottle = &bottles[0];
        let description = metadata
            .get(&bottle.record_label)
            .map(describe_metadata)
            .unwrap_or_else(|| "unknown device".into());
        eprintln!("Using the only recovery device: {description}");
        return Ok(0);
    }

    eprintln!("Choose the device whose login passcode you know:");
    for (index, bottle) in bottles.iter().enumerate() {
        let description = metadata
            .get(&bottle.record_label)
            .map(describe_metadata)
            .unwrap_or_else(|| "unknown device".into());
        eprintln!("  {}) {description}", index + 1);
        eprintln!("     {}", bottle.record_label);
    }
    loop {
        let answer = prompt_line(format!(
            "Recovery device number (1-{}, or q to cancel): ",
            bottles.len()
        ))?;
        if answer.trim().eq_ignore_ascii_case("q") || answer.trim().is_empty() {
            return Err(Error::Refused(
                "recovery cancelled; no escrow attempt was spent".into(),
            ));
        }
        let Ok(number) = answer.trim().parse::<usize>() else {
            eprintln!("Enter one of the displayed device numbers, or q to cancel.");
            continue;
        };
        if !(1..=bottles.len()).contains(&number) {
            eprintln!("Enter one of the displayed device numbers, or q to cancel.");
            continue;
        }
        return Ok(number - 1);
    }
}

fn find_credential<'a>(credentials: &'a [Credential], id: &str) -> Result<&'a Credential> {
    let matches: Vec<_> = credentials
        .iter()
        .filter(|credential| credential.id == id || credential.id.starts_with(id))
        .collect();
    match matches.as_slice() {
        [item] => Ok(*item),
        [] => Err(Error::Config(format!("no credential matches {id}"))),
        _ => Err(Error::Config(format!(
            "credential id prefix {id} is ambiguous"
        ))),
    }
}

fn short_id(id: &str) -> &str {
    id.get(..id.len().min(12)).unwrap_or(id)
}

fn prompt_two_factor(prompt: auth::TwoFactorPrompt) -> Result<auth::TwoFactorResponse> {
    match prompt {
        auth::TwoFactorPrompt::Choose(methods) => loop {
            eprintln!("Choose how to receive the Apple verification code:");
            for (index, method) in methods.iter().enumerate() {
                eprintln!("  {}. {}", index + 1, describe_two_factor_method(method));
            }
            let answer = prompt_line("Method number (or q to cancel): ")?;
            let answer = answer.trim();
            if answer.eq_ignore_ascii_case("q") {
                return Ok(auth::TwoFactorResponse::Cancel);
            }
            let Ok(number) = answer.parse::<usize>() else {
                eprintln!("Enter one of the displayed method numbers.");
                continue;
            };
            if !(1..=methods.len()).contains(&number) {
                eprintln!("Enter one of the displayed method numbers.");
                continue;
            }
            return Ok(auth::TwoFactorResponse::Choose(number - 1));
        },
        auth::TwoFactorPrompt::Code(method) => {
            eprintln!(
                "Apple sent a verification code using {}.",
                describe_two_factor_method(&method)
            );
            loop {
                let answer = prompt_line("6-digit code ([r]esend, change [m]ethod, [q]uit): ")?;
                let answer = answer.trim();
                if answer.eq_ignore_ascii_case("r") {
                    return Ok(auth::TwoFactorResponse::Resend);
                }
                if answer.eq_ignore_ascii_case("m") {
                    return Ok(auth::TwoFactorResponse::ChangeMethod);
                }
                if answer.eq_ignore_ascii_case("q") {
                    return Ok(auth::TwoFactorResponse::Cancel);
                }
                if answer.len() == 6 && answer.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Ok(auth::TwoFactorResponse::Code(Zeroizing::new(
                        answer.to_owned(),
                    )));
                }
                eprintln!("Enter a six-digit code, r, m, or q.");
            }
        }
    }
}

fn describe_two_factor_method(method: &auth::TwoFactorMethod) -> String {
    match method {
        auth::TwoFactorMethod::TrustedDevices => "trusted Apple devices".into(),
        auth::TwoFactorMethod::Phone(factor) => format!(
            "{} to {}",
            if factor.mode == "voice" {
                "voice call"
            } else {
                "text message"
            },
            credential::printable(&factor.display)
        ),
    }
}

fn prompt_line(prompt: impl AsRef<str>) -> Result<String> {
    eprint!("{}", prompt.as_ref());
    io::stderr()
        .flush()
        .map_err(|error| Error::io("stderr", error))?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| Error::io("stdin", error))?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).map_err(|error| Error::io("terminal", error))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn exit_code(error: &Error) -> i32 {
    match error {
        Error::Config(_) => 2,
        Error::AuthenticationRequired(_) => 3,
        Error::Refused(_) => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use keychain::paths::atomic_write_private;
    use keychain::security::{KeyUsage, Purpose};

    #[test]
    fn full_logout_recovers_from_an_obsolete_octagon_layout() {
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(
            root.path().join("config"),
            root.path().join("state"),
            root.path().join("runtime"),
        )
        .unwrap_or_else(|error| panic!("test paths: {error}"));
        let backend = SoftwareFileBackend::new(paths.clone());
        backend
            .generate_p384(KeyUsage::Signing)
            .unwrap_or_else(|error| panic!("generate key: {error}"));
        let obsolete = backend
            .seal(Purpose::Octagon, br#"{"joined":true,"sponsor":null}"#)
            .unwrap_or_else(|error| panic!("seal obsolete state: {error}"));
        atomic_write_private(&paths.octagon_file(), &obsolete)
            .unwrap_or_else(|error| panic!("write obsolete state: {error}"));
        let store = StateStore::new(&paths, &backend);

        command_logout(true, &paths, &backend, &store)
            .unwrap_or_else(|error| panic!("full logout: {error}"));

        for path in [
            paths.octagon_file(),
            paths.keys_file(),
            paths.software_key_file(),
        ] {
            assert!(!path.exists(), "{} should be removed", path.display());
        }
    }

    #[test]
    fn setup_accepts_optional_account_and_bottle_selection() {
        let cli = Cli::try_parse_from([
            "keychain",
            "setup",
            "--username",
            "person@example.com",
            "--bottle",
            "com.apple.icdp.record.test",
        ])
        .unwrap_or_else(|error| panic!("parse setup: {error}"));

        match cli.command {
            Command::Setup { username, bottle } => {
                assert_eq!(username.as_deref(), Some("person@example.com"));
                assert_eq!(bottle.as_deref(), Some("com.apple.icdp.record.test"));
            }
            command => panic!("expected setup command, got {command:?}"),
        }
    }
}
