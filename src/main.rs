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
    AccountState, Credential, DeviceIdentity, OctagonState, OctagonTrustState, PasskeyCredential,
    VaultState,
};
use keychain::passkey;
use keychain::paths::{AppPaths, StateLock};
#[cfg(test)]
use keychain::security::SoftwareFileBackend;
use keychain::security::{SecurityBackend, backend_for_config};
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
        /// Recover trust with a replacement peer, preserving existing keys and cache.
        #[arg(long)]
        repair: bool,
    },
    /// Download and decrypt the latest password snapshot.
    Sync,
    /// List locally cached logins and passkeys without revealing secrets.
    List {
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Reveal one locally cached credential.
    Show {
        id: String,
        /// Emit one JSON object, including the password and current TOTP code.
        #[arg(long)]
        json: bool,
    },
    /// Generate the current verification code for one credential.
    Totp { id: String },
    /// Protect one existing login or passkey with biometrics, retaining recovery data.
    Protect {
        id: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Inspect or exercise locally cached passkeys.
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommand,
    },
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
enum PasskeyCommand {
    /// Produce a diagnostic WebAuthn assertion after an interactive approval.
    Assert {
        id: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        origin: String,
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
    if let Err(error) = keychain_sep_driver::memory::make_process_nondumpable() {
        eprintln!("keychain: could not protect process memory: {error}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("keychain: {error}");
        std::process::exit(exit_code(&error));
    }
}

fn run(cli: Cli) -> Result<()> {
    let paths = AppPaths::discover()?;
    let config = Config::load(&paths)?;
    let selected_backend = backend_for_config(&config, &paths)?;
    let backend = selected_backend.as_ref();
    let store = StateStore::new(&paths, backend);
    match cli.command {
        Command::Anisette { command } => command_anisette(command, &paths, config),
        Command::Setup { username, bottle } => {
            let _lock = StateLock::acquire(&paths)?;
            command_setup(username, bottle.as_deref(), &paths, config, backend, &store)
        }
        Command::Login { username } => {
            let _lock = StateLock::acquire(&paths)?;
            command_login(username, &paths, config, backend, &store)
        }
        Command::Bottles => {
            let _lock = StateLock::acquire(&paths)?;
            command_bottles(&paths, config, backend, &store)
        }
        Command::Join { bottle, repair } => {
            let _lock = StateLock::acquire(&paths)?;
            command_join(bottle.as_deref(), repair, &paths, config, backend, &store)
        }
        Command::Sync => {
            let _lock = StateLock::acquire(&paths)?;
            command_sync(&paths, config, backend, &store)
        }
        Command::List { query, json } => command_list(query.as_deref(), json, &config, &store),
        Command::Show { id, json } => command_show(&id, json, &config, &store),
        Command::Totp { id } => command_totp(&id, &config, &store),
        Command::Protect { id, socket } => {
            let _lock = StateLock::acquire(&paths)?;
            command_protect(&id, socket, &paths, &config, backend, &store)
        }
        Command::Passkey { command } => {
            let _lock = StateLock::acquire(&paths)?;
            command_passkey(command, &config, backend, &store)
        }
        Command::Status => command_status(&paths, &config, backend, &store),
        Command::Logout { forget_device } => {
            let _lock = StateLock::acquire(&paths)?;
            command_logout(forget_device, &paths, &config, backend, &store)
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
    if store
        .load_trust_repair()?
        .is_some_and(|journal| journal.phase() != keychain::recovery::RepairPhase::Committed)
    {
        return Err(Error::Config(
            "a trust repair is pending; resume it with `keychain join --repair`".into(),
        ));
    }
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
        false,
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
    repair: bool,
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
    let pending_repair = store
        .load_trust_repair()?
        .is_some_and(|journal| journal.phase() != keychain::recovery::RepairPhase::Committed);
    if repair || pending_repair {
        return repair_octagon(
            requested_label,
            &account,
            &device,
            &anisette,
            backend,
            store,
            &config,
        );
    }
    join_octagon(
        requested_label,
        &account,
        &device,
        &anisette,
        backend,
        store,
        state,
        None,
        false,
    )
}

fn checkpoint_join(store: &StateStore<'_>, state: &OctagonState, repair: bool) -> Result<()> {
    if repair {
        keychain::recovery::TrustRepair::checkpoint(store, state)
    } else {
        store.save_octagon(state)
    }
}

fn repair_octagon(
    requested_label: Option<&str>,
    account: &AccountState,
    device: &DeviceIdentity,
    anisette: &dyn anisette::AnisetteProvider,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    config: &Config,
) -> Result<()> {
    use keychain::recovery::{RepairPhase, TrustRepair};
    let mut journal = TrustRepair::prepare(store, account, device, backend)?;
    let mut current_account = account.clone();
    if journal.phase() == RepairPhase::Prepared {
        eprintln!("Repairing Octagon trust; existing peer keys and cached items are retained.");
        let mut escrow_pet = None;
        if journal.candidate().trust_state == OctagonTrustState::IdentityReady {
            // A provider change can invalidate old service tokens. This recovery
            // already needs a fresh PET: refresh the account in the same SRP/2FA
            // exchange, retain its PET only in memory, and keep the active peer.
            let (account, refreshed_device, _active_peer, pet) = authenticate_and_prepare(
                Some(current_account.username.clone()),
                anisette,
                backend,
                store,
            )?;
            if &refreshed_device != device {
                return Err(Error::Security(
                    "device identity changed during trust repair".into(),
                ));
            }
            validate_account_binding(&account, journal.candidate())?;
            current_account = account;
            escrow_pet = Some(pet);
        }
        join_octagon(
            requested_label,
            &current_account,
            device,
            anisette,
            backend,
            store,
            journal.candidate().clone(),
            escrow_pet,
            true,
        )?;
        journal = store
            .load_trust_repair()?
            .ok_or_else(|| Error::Security("trust-repair journal disappeared".into()))?;
        if !matches!(
            journal.candidate().trust_state,
            OctagonTrustState::JoinedSponsorRetirementVerified { .. }
        ) {
            return Ok(());
        }
        let client = octagon::OctagonClient::new(&current_account, device, anisette, backend)?;
        eprintln!("Verifying a complete sync with the replacement peer alone…");
        let projection = client.sync_self_credentials(journal.candidate())?;
        save_synced_projection(projection, config, backend, store)?;
        journal = journal.snapshot_verified(store)?;
    }
    let client = octagon::OctagonClient::new(&current_account, device, anisette, backend)?;
    let journal = journal.commit(store, |state| client.retire_verified_sponsor(state))?;
    println!("Octagon trust repaired as {}", journal.candidate().peer_id);
    println!("Verified a complete snapshot; previous peer keys are retained locally.");
    Ok(())
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
    repair: bool,
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
        return finish_sponsor_join(&client, store, &mut state, repair);
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
    checkpoint_join(store, &state, repair)?;
    finish_sponsor_join(&client, store, &mut state, repair)
}

fn finish_sponsor_join(
    client: &octagon::OctagonClient<'_>,
    store: &StateStore<'_>,
    state: &mut OctagonState,
    repair: bool,
) -> Result<()> {
    let outcome = client.join_with_sponsor(state)?;
    // This checkpoint makes retirement crash-safe: after successful verification, a restart can
    // delete the old key without needing it to decrypt the sponsor shares again.
    checkpoint_join(store, state, repair)?;
    let (uploaded_tlk_shares, awaiting_reason) = match outcome {
        octagon::JoinOutcome::SponsorRetirementReady {
            uploaded_tlk_shares,
        } => {
            if !repair {
                // Self-share coverage alone does not prove the desired views
                // are readable. Keep the sponsor until an independent complete
                // snapshot succeeds, including every encrypted Passwords item.
                let _ = client.sync_self_credentials(state)?;
                client.retire_verified_sponsor(state)?;
                store.save_octagon(state)?;
            }
            (uploaded_tlk_shares, None)
        }
        octagon::JoinOutcome::AwaitingSelfShareVerification {
            uploaded_tlk_shares,
            reason,
        } => (uploaded_tlk_shares, Some(reason)),
    };
    println!(
        "{} Octagon as {}",
        if repair {
            "replacement peer joined"
        } else {
            "joined"
        },
        state.peer_id
    );
    if uploaded_tlk_shares > 0 {
        println!(
            "uploaded {} self-addressed TLK share(s)",
            uploaded_tlk_shares
        );
    }
    if awaiting_reason.is_none() && !repair {
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
    save_synced_projection(projection, &config, backend, store)
}

fn save_synced_projection(
    projection: credential::Projection,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let count = projection.credentials.len();
    let previous = store.load_vault()?;
    let (credentials, login_ids) = keychain::protection::login::reconcile_synced(
        projection.credentials,
        previous
            .as_ref()
            .map(|vault| vault.credentials.as_slice())
            .unwrap_or_default(),
        config,
        store.paths(),
        backend,
        store,
    )?;
    let passkeys = passkey::reconcile_synced_passkeys(
        projection.passkeys,
        previous
            .as_ref()
            .map(|v| v.passkeys.as_slice())
            .unwrap_or_default(),
        backend,
        config.credential_broker.as_deref(),
        &login_ids,
    )?;
    let passkey_count = passkeys.len();
    store.save_vault(&VaultState {
        schema_version: 1,
        synced_at: unix_now(),
        credentials,
        passkeys,
    })?;
    keychain::protection::login::finish_synced(store.paths(), backend, &login_ids)?;
    println!("synced {count} credential(s)");
    println!("synced {passkey_count} passkey(s)");
    Ok(())
}

fn command_list(
    query: Option<&str>,
    json: bool,
    config: &Config,
    store: &StateStore<'_>,
) -> Result<()> {
    let index = visible_index(config, store)?;
    let query = query.unwrap_or_default().trim().to_ascii_lowercase();
    let mut items: Vec<_> = index
        .credentials
        .iter()
        .filter(|item| {
            query.is_empty()
                || item.id.to_ascii_lowercase().starts_with(&query)
                || item.domain.to_ascii_lowercase().contains(&query)
                || item.username.to_ascii_lowercase().contains(&query)
                || item.title.to_ascii_lowercase().contains(&query)
        })
        .map(VaultItem::Metadata)
        .chain(
            passkey::search(&index.passkeys, &query)
                .into_iter()
                .map(VaultItem::Passkey),
        )
        .collect();
    items.sort_by(|a, b| {
        b.recency()
            .total_cmp(&a.recency())
            .then_with(|| a.site().cmp(b.site()))
            .then_with(|| a.username().cmp(b.username()))
    });
    if json {
        let mut output = Vec::new();
        for item in items {
            output.push(match item {
            VaultItem::Metadata(item)=>serde_json::json!({"schema_version":1,"kind":"login","id":item.id,
                "title":item.title,"domain":item.domain,"username":item.username,"totp":item.has_totp}),
            VaultItem::Passkey(item)=>serde_json::json!({"schema_version":1,"kind":"passkey","id":item.id,
                "rp_id":item.rp_id,"username":item.username,"display_name":item.display_name,
                "credential_fingerprint":passkey::credential_fingerprint(item)?,"algorithm":"ES256","storage":item.provenance}),
            VaultItem::Login(_)=>return Err(Error::Security("unexpected secret-bearing list item".into())),
        });
        }
        println!("{}", serde_json::to_string(&output)?);
    } else {
        for item in items {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                short_id(item.id()),
                item.kind(),
                credential::printable(item.site()),
                credential::printable(item.username()),
                credential::printable(item.title())
            );
        }
    }
    Ok(())
}
fn command_show(id: &str, json: bool, config: &Config, store: &StateStore<'_>) -> Result<()> {
    let index = visible_index(config, store)?;
    refuse_missing_login_match(config, &index, id)?;
    match find_index_item(&index, id)? {
        VaultItem::Metadata(item) => {
            if let Some(route) = config
                .protected_logins
                .iter()
                .find(|route| route.id == item.id)
            {
                command_show_protected(item, route, json, config)
            } else {
                let vault = require_vault(store)?;
                command_show_login(find_credential(&vault.credentials, &item.id)?, json)
            }
        }
        VaultItem::Passkey(item) => command_show_passkey(item, json),
        VaultItem::Login(_) => Err(Error::Security(
            "unexpected secret-bearing index item".into(),
        )),
    }
}
fn reveal_protected(
    route: &keychain::config::LoginRoute,
    field: keychain::broker::login::RevealField,
    config: &Config,
) -> Result<keychain::broker::login::RevealedLogin> {
    let socket = config
        .credential_broker
        .as_ref()
        .ok_or_else(|| Error::Config("protected login requires its broker".into()))?;
    keychain::broker::login::reveal(
        socket,
        &keychain::broker::login::LoginSelection {
            id: route.id.clone(),
            revision: route.revision,
            content_binding: route.content_binding.clone(),
        },
        field,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
}
fn command_show_protected(
    item: &keychain::broker::login::LoginMetadata,
    route: &keychain::config::LoginRoute,
    json: bool,
    config: &Config,
) -> Result<()> {
    let value = reveal_protected(route, keychain::broker::login::RevealField::All, config)?;
    let password = value
        .password
        .as_ref()
        .map(|value| value.as_str())
        .ok_or_else(|| Error::Security("broker omitted selected password field".into()))?;
    let notes = value
        .notes
        .as_ref()
        .map(|value| value.as_str())
        .ok_or_else(|| Error::Security("broker omitted selected notes field".into()))?;
    let now = unix_now().max(0) as u64;
    if json {
        #[derive(serde::Serialize)]
        struct Code<'a> {
            code: &'a str,
            expires_at: u64,
            period: u64,
            remaining_seconds: u64,
        }
        #[derive(serde::Serialize)]
        struct Show<'a> {
            schema_version: u32,
            kind: &'static str,
            id: &'a str,
            title: &'a str,
            domain: &'a str,
            username: &'a str,
            password: &'a str,
            notes: &'a str,
            totp: Option<Code<'a>>,
        }
        let output = Show {
            schema_version: 1,
            kind: "login",
            id: &item.id,
            title: &item.title,
            domain: &item.domain,
            username: &item.username,
            password,
            notes,
            totp: value.totp.as_ref().map(|code| Code {
                code: &code.code,
                expires_at: code.expires,
                period: code.period,
                remaining_seconds: code.expires.saturating_sub(now),
            }),
        };
        serde_json::to_writer(std::io::stdout().lock(), &output)?;
        println!();
    } else {
        println!("id: {}", item.id);
        println!("title: {}", credential::printable(&item.title));
        println!("domain: {}", credential::printable(&item.domain));
        println!("username: {}", credential::printable(&item.username));
        println!("password: {password}");
        if !notes.is_empty() {
            let printable = zeroize::Zeroizing::new(credential::printable(notes));
            println!("notes: {}", printable.as_str());
        }
        if let Some(code) = &value.totp {
            println!(
                "totp: {} ({}s remaining)",
                code.code,
                code.expires.saturating_sub(now)
            );
        }
    }
    Ok(())
}

fn command_show_login(item: &Credential, json: bool) -> Result<()> {
    require_software_login(item)?;
    let now = unix_now().max(0) as u64;
    let totp = if item.totp_uri.is_empty() {
        None
    } else {
        Some(
            keychain::totp::generate(&item.totp_uri, now).ok_or_else(|| {
                Error::InvalidData("credential has an invalid TOTP configuration".into())
            })?,
        )
    };
    if json {
        let totp = totp.as_ref().map(|totp| {
            serde_json::json!({
                "code": totp.code,
                "expires_at": totp.expires,
                "period": totp.period,
                "remaining_seconds": totp.expires.saturating_sub(now),
            })
        });
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema_version": 1,
                "kind": "login",
                "id": item.id,
                "title": item.title,
                "domain": item.domain,
                "username": item.username,
                "password": item.password,
                "notes": item.notes,
                "totp": totp,
            }))?
        );
        return Ok(());
    }
    println!("id: {}", item.id);
    println!("title: {}", credential::printable(&item.title));
    println!("domain: {}", credential::printable(&item.domain));
    println!("username: {}", credential::printable(&item.username));
    println!("password: {}", item.password);
    if !item.notes.is_empty() {
        println!("notes: {}", credential::printable(&item.notes));
    }
    if let Some(totp) = totp {
        println!(
            "totp: {} ({}s remaining)",
            totp.code,
            totp.expires.saturating_sub(now)
        );
    }
    Ok(())
}

fn command_show_passkey(item: &PasskeyCredential, json: bool) -> Result<()> {
    let fingerprint = passkey::credential_fingerprint(item)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema_version": 1,
                "kind": "passkey",
                "id": item.id,
                "rp_id": item.rp_id,
                "username": item.username,
                "display_name": item.display_name,
                "credential_fingerprint": fingerprint,
                "algorithm": "ES256",
                "storage": item.provenance,
            }))?
        );
        return Ok(());
    }
    println!("id: {}", item.id);
    println!("kind: passkey");
    println!(
        "storage: {}",
        match item.provenance {
            keychain::model::PasskeyProvenance::DeviceBound => "this device",
            keychain::model::PasskeyProvenance::Synced => "iCloud",
        }
    );
    println!("relying party: {}", credential::printable(&item.rp_id));
    println!("username: {}", credential::printable(&item.username));
    if !item.display_name.is_empty() {
        println!(
            "display name: {}",
            credential::printable(&item.display_name)
        );
    }
    println!("algorithm: ES256");
    println!("credential fingerprint: {fingerprint}");
    Ok(())
}

fn require_software_login(item: &Credential) -> Result<()> {
    if item.protected {
        return Err(Error::Refused(
            "this login requires biometric verification through its broker".into(),
        ));
    }
    Ok(())
}

fn command_totp(id: &str, config: &Config, store: &StateStore<'_>) -> Result<()> {
    let index = visible_index(config, store)?;
    refuse_missing_login_match(config, &index, id)?;
    let VaultItem::Metadata(item) = find_index_item(&index, id)? else {
        return Err(Error::Config("selected item is not a login".into()));
    };
    if let Some(route) = config
        .protected_logins
        .iter()
        .find(|route| route.id == item.id)
    {
        let value = reveal_protected(route, keychain::broker::login::RevealField::Totp, config)?;
        let code = value
            .totp
            .as_ref()
            .ok_or_else(|| Error::Security("broker omitted selected verification code".into()))?;
        println!("{}", code.code);
    } else {
        let vault = require_vault(store)?;
        let item = find_credential(&vault.credentials, &item.id)?;
        require_software_login(item)?;
        let code = keychain::totp::generate(&item.totp_uri, unix_now().max(0) as u64).ok_or_else(
            || Error::InvalidData("credential has no usable TOTP configuration".into()),
        )?;
        println!("{}", code.code);
    }
    Ok(())
}
fn command_protect(
    id: &str,
    socket: Option<PathBuf>,
    paths: &AppPaths,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let vault = require_vault(store)?;
    let item = find_vault_item(&vault, id)?;
    let socket = socket
        .or_else(|| config.credential_broker.clone())
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "/run/keychain/broker-{}.sock",
                keychain_sep_driver::peer::effective_uid()
            ))
        });
    eprintln!("Protecting the existing credential; your desktop will ask for a fingerprint.");
    let outcome = match item {
        VaultItem::Login(item) => {
            keychain::protection::login::migrate_login(paths, backend, store, &item.id, &socket)?
        }
        VaultItem::Passkey(item) => {
            keychain::protection::migrate_passkey(paths, backend, store, &item.id, &socket)?
        }
        VaultItem::Metadata(_) => {
            return Err(Error::Security("unexpected migration source".into()));
        }
    };
    println!(
        "protected {} (revision {})",
        outcome.record, outcome.revision
    );
    println!("software recovery copy retained; no Apple records changed");
    Ok(())
}

fn command_passkey(
    command: PasskeyCommand,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    match command {
        PasskeyCommand::Assert {
            id,
            challenge,
            origin,
        } => command_passkey_assert(&id, &challenge, &origin, config, backend, store),
    }
}

fn command_passkey_assert(
    id: &str,
    challenge: &str,
    origin: &str,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let vault = visible_index(config, store)?;
    let item = find_passkey(&vault.passkeys, id)?;
    eprintln!("Passkey sign-in requested");
    eprintln!("relying party: {}", credential::printable(&item.rp_id));
    eprintln!("origin: {}", credential::printable(origin));
    eprintln!("account: {}", credential::printable(&item.username));
    if keychain::protection::is_broker_key(&item.signing_key) {
        let socket=config.credential_broker.as_ref().ok_or_else(||Error::Config(
            "this passkey requires its credential broker; resume `keychain protect` if migration was interrupted".into()))?;
        let details = serde_json::json!({"challenge":challenge,"rpId":item.rp_id,
            "allowCredentials":[{"type":"public-key","id":item.credential_id}],"userVerification":"required",
            "extensions":{"remoteDesktopClientOverride":{"origin":origin,"sameOriginWithAncestors":true}}});
        let result = keychain::broker::call(
            socket,
            keychain::broker::Operation::Assert {
                record: item.id.clone(),
                request_details_json: details.to_string(),
            },
        )?;
        let response = result
            .get("responseJson")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::Security("broker returned no assertion".into()))?;
        println!("{response}");
        return Ok(());
    }
    let answer = prompt_line("Approve this sign-in? [y/N]: ")?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Err(Error::Refused("passkey sign-in was not approved".into()));
    }
    let assertion = passkey::assertion_for_origin(item, challenge, origin, backend)?;
    println!("{}", serde_json::to_string(&assertion)?);
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
            println!("vault credentials: {}", vault.credentials.len());
            println!("vault passkeys: {}", vault.passkeys.len());
            println!("last sync: {}", vault.synced_at);
        }
        None => println!("vault: empty"),
    }
    if let Some(repair) = store.load_trust_repair()? {
        println!(
            "Octagon trust repair: {:?}; retained peer identities: {}",
            repair.phase(),
            repair.retained().len()
        );
        let recovery_state = match repair.candidate().trust_state {
            OctagonTrustState::IdentityReady => "no recovered sponsor saved",
            OctagonTrustState::SponsorRecovered { .. } => "recovered sponsor saved",
            OctagonTrustState::JoinedAwaitingTlkVerification { .. } => {
                "joined; self recovery pending"
            }
            OctagonTrustState::JoinedSponsorRetirementVerified { .. } => {
                "joined; self recovery verified"
            }
            OctagonTrustState::Joined => "joined",
        };
        println!("repair recovery checkpoint: {recovery_state}");
        if repair.phase() != keychain::recovery::RepairPhase::Committed {
            println!("resume trust repair: keychain join --repair");
        }
    }
    Ok(())
}

fn command_logout(
    forget_device: bool,
    paths: &AppPaths,
    config: &Config,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<()> {
    let repair = match store.load_trust_repair() {
        Ok(repair) => repair,
        Err(error) if forget_device => {
            eprintln!(
                "warning: trust-repair state could not be decoded ({error}); performing the requested full local reset"
            );
            None
        }
        Err(error) => return Err(error),
    };
    if let Some(socket) = &config.credential_broker {
        let updated = keychain::broker::call(
            socket,
            keychain::broker::Operation::SetSyncedInventory { records: vec![] },
        )?;
        if updated.get("updated").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(Error::Security(
                "broker did not disable account-synced passkeys".into(),
            ));
        }
    }
    match store.load_vault() {
        Ok(Some(vault)) => {
            for passkey in &vault.passkeys {
                let _ = backend.destroy_key(&passkey.signing_key);
            }
        }
        Ok(None) => {}
        Err(error) if forget_device => {
            eprintln!(
                "warning: vault state could not be decoded ({error}); performing the requested full local reset"
            );
        }
        Err(error) => return Err(error),
    }
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
    if let Some(repair) = repair {
        destroy_octagon_keys(backend, repair.candidate());
        for state in repair.retained() {
            destroy_octagon_keys(backend, state);
        }
    }
    for path in [
        paths.account_file(),
        paths.octagon_file(),
        paths.trust_repair_file(),
        paths.vault_file(),
        paths.vault_index_file(),
        paths.previous_vault_file(),
    ] {
        store.remove_if_exists(&path)?;
    }
    if forget_device {
        if paths.protection_dir().exists() {
            std::fs::remove_dir_all(paths.protection_dir())
                .map_err(|e| Error::io(paths.protection_dir(), e))?;
        }
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

fn refuse_missing_login_match(
    config: &Config,
    index: &keychain::store::VaultIndex,
    id: &str,
) -> Result<()> {
    if config.protected_logins.iter().any(|route| {
        route.id.starts_with(id) && !index.credentials.iter().any(|item| item.id == route.id)
    }) {
        return Err(Error::Refused(
            "selected protected login is missing or disabled; refusing software fallback".into(),
        ));
    }
    Ok(())
}

fn visible_index(config: &Config, store: &StateStore<'_>) -> Result<keychain::store::VaultIndex> {
    let mut index = match store.load_index()? {
        Some(index) => index,
        None if !store.has_vault()? => keychain::store::VaultIndex {
            schema_version: 1,
            source_sha256: String::new(),
            protected_login_ids: vec![],
            credentials: vec![],
            passkeys: vec![],
        },
        None if config.protected_logins.is_empty() => {
            keychain::store::VaultIndex::from_vault(&require_vault(store)?, String::new())
        }
        None => {
            return Err(Error::Refused(
                "protected cache metadata is missing; resume protection to repair it".into(),
            ));
        }
    };
    if index
        .protected_login_ids
        .iter()
        .any(|id| !config.protected_logins.iter().any(|route| &route.id == id))
    {
        return Err(Error::Refused(
            "protected login routing is missing; resume protection to restore it".into(),
        ));
    }
    index.credentials.retain(|item| {
        !config
            .protected_logins
            .iter()
            .any(|route| route.id == item.id)
    });
    if let Some(socket) = &config.credential_broker {
        let native: Vec<PasskeyCredential> = serde_json::from_value(keychain::broker::call(
            socket,
            keychain::broker::Operation::ListCredentials,
        )?)?;
        let mut metadata = VaultState {
            schema_version: 1,
            synced_at: 0,
            credentials: vec![],
            passkeys: std::mem::take(&mut index.passkeys),
        };
        merge_native_inventory(&mut metadata, native)?;
        index.passkeys = std::mem::take(&mut metadata.passkeys);
        for login in keychain::protection::login::inventory(config)? {
            if index
                .passkeys
                .iter()
                .any(|item| item.id == login.metadata.id)
            {
                return Err(Error::Security("login/passkey inventory collision".into()));
            }
            index.credentials.push(login.metadata);
        }
    }
    Ok(index)
}

fn merge_native_inventory(vault: &mut VaultState, records: Vec<PasskeyCredential>) -> Result<()> {
    use keychain::model::PasskeyProvenance;
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        if !seen.insert(record.id.clone()) {
            return Err(Error::Security("duplicate broker inventory record".into()));
        }
        if record.provenance != PasskeyProvenance::DeviceBound {
            continue;
        }
        if let Some(previous) = vault.passkeys.iter_mut().find(|p| p.id == record.id) {
            if previous.provenance != PasskeyProvenance::DeviceBound
                || previous.signing_key != record.signing_key
                || previous.rp_id != record.rp_id
                || previous.credential_id != record.credential_id
                || previous.user_handle != record.user_handle
            {
                return Err(Error::Security(
                    "broker native credential collides with a different local identity".into(),
                ));
            }
            *previous = record;
        } else {
            vault.passkeys.push(record);
        }
    }
    Ok(())
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

#[derive(Clone, Copy)]
enum VaultItem<'a> {
    Login(&'a Credential),
    Metadata(&'a keychain::broker::login::LoginMetadata),
    Passkey(&'a PasskeyCredential),
}

impl<'a> VaultItem<'a> {
    fn id(self) -> &'a str {
        match self {
            Self::Login(item) => &item.id,
            Self::Metadata(item) => &item.id,
            Self::Passkey(item) => &item.id,
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::Login(_) | Self::Metadata(_) => "login",
            Self::Passkey(_) => "passkey",
        }
    }

    fn site(self) -> &'a str {
        match self {
            Self::Login(item) => &item.domain,
            Self::Metadata(item) => &item.domain,
            Self::Passkey(item) => &item.rp_id,
        }
    }

    fn username(self) -> &'a str {
        match self {
            Self::Login(item) => &item.username,
            Self::Metadata(item) => &item.username,
            Self::Passkey(item) => &item.username,
        }
    }

    fn title(self) -> &'a str {
        match self {
            Self::Login(item) => &item.title,
            Self::Metadata(item) => &item.title,
            Self::Passkey(item) => &item.display_name,
        }
    }

    fn recency(self) -> f64 {
        match self {
            Self::Login(item) => item.recency(),
            Self::Metadata(item) => {
                if item.last_used > 0.0 {
                    item.last_used
                } else {
                    item.modified_at
                }
            }
            Self::Passkey(item) if item.modified_at > 0.0 => item.modified_at,
            Self::Passkey(item) => item.created_at,
        }
    }
}

fn select_item<'a>(items: impl Iterator<Item = VaultItem<'a>>, id: &str) -> Result<VaultItem<'a>> {
    let matches: Vec<_> = items
        .filter(|item| item.id() == id || item.id().starts_with(id))
        .collect();
    match matches.as_slice() {
        [item] => Ok(*item),
        [] => Err(Error::Config(format!("no vault item matches {id}"))),
        _ => Err(Error::Config(format!(
            "vault item id prefix {id} is ambiguous"
        ))),
    }
}
fn find_vault_item<'a>(vault: &'a VaultState, id: &str) -> Result<VaultItem<'a>> {
    select_item(
        vault
            .credentials
            .iter()
            .map(VaultItem::Login)
            .chain(vault.passkeys.iter().map(VaultItem::Passkey)),
        id,
    )
}
fn find_index_item<'a>(index: &'a keychain::store::VaultIndex, id: &str) -> Result<VaultItem<'a>> {
    select_item(
        index
            .credentials
            .iter()
            .map(VaultItem::Metadata)
            .chain(index.passkeys.iter().map(VaultItem::Passkey)),
        id,
    )
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

fn find_passkey<'a>(passkeys: &'a [PasskeyCredential], id: &str) -> Result<&'a PasskeyCredential> {
    let matches: Vec<_> = passkeys
        .iter()
        .filter(|passkey| passkey.id == id || passkey.id.starts_with(id))
        .collect();
    match matches.as_slice() {
        [item] => Ok(*item),
        [] => Err(Error::Config(format!("no passkey matches {id}"))),
        _ => Err(Error::Config(format!(
            "passkey id prefix {id} is ambiguous"
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
    fn protect_is_a_general_command_without_a_passkey_alias() -> Result<()> {
        let cli = Cli::try_parse_from([
            "keychain",
            "protect",
            "12345678",
            "--socket",
            "/run/keychain/test.sock",
        ])
        .map_err(|error| Error::Config(error.to_string()))?;
        assert!(matches!(cli.command, Command::Protect { .. }));
        assert!(Cli::try_parse_from(["keychain", "passkey", "protect", "12345678"]).is_err());
        Ok(())
    }
    #[test]
    fn missing_protected_route_cannot_resolve_to_a_software_prefix_match() -> Result<()> {
        let mut config = Config::default();
        config.protected_logins.push(keychain::config::LoginRoute {
            id: "12345678-0000-4000-8000-000000000001".into(),
            account_fingerprint: String::new(),
            recipient_id: String::new(),
            revision: 1,
            content_binding: String::new(),
        });
        let source = Credential {
            protected: true,
            id: "12345678-1111-4000-8000-000000000002".into(),
            domain: "example.com".into(),
            username: "synthetic".into(),
            password: "synthetic".into(),
            title: String::new(),
            notes: String::new(),
            totp_uri: String::new(),
            modified_at: 0.0,
            last_used: 0.0,
        };
        assert!(command_show_login(&source, true).is_err());
        let item = keychain::broker::login::LoginMetadata::from(&source);
        let index = keychain::store::VaultIndex {
            schema_version: 1,
            source_sha256: String::new(),
            protected_login_ids: vec![],
            credentials: vec![item],
            passkeys: vec![],
        };
        assert!(refuse_missing_login_match(&config, &index, "12345678").is_err());
        assert!(
            refuse_missing_login_match(&config, &index, "12345678-1111-4000-8000-000000000002")
                .is_ok()
        );
        Ok(())
    }
    #[test]
    fn visible_inventory_adds_native_credentials_without_hiding_unmigrated_items_or_changing_identity()
    -> Result<()> {
        use keychain::model::PasskeyProvenance;
        let native = PasskeyCredential {
            provenance: PasskeyProvenance::DeviceBound,
            id: uuid::Uuid::new_v4().to_string(),
            rp_id: "example.com".into(),
            credential_id: "AQ".into(),
            user_handle: "Ag".into(),
            username: "user".into(),
            display_name: "User".into(),
            created_at: 0.0,
            modified_at: 0.0,
            signing_key: keychain::security::KeyRef {
                backend_id: "sep-native-v1".into(),
                key_id: "native".into(),
                usage: KeyUsage::WebAuthnSigning,
                algorithm: keychain::security::KeyAlgorithm::P256,
            },
        };
        let mut synced = native.clone();
        synced.id = uuid::Uuid::new_v4().to_string();
        synced.provenance = PasskeyProvenance::Synced;
        synced.signing_key.backend_id = "software-file".into();
        let mut vault = VaultState {
            schema_version: 1,
            synced_at: 0,
            credentials: vec![],
            passkeys: vec![synced.clone()],
        };
        merge_native_inventory(&mut vault, vec![native.clone()])?;
        assert_eq!(vault.passkeys, vec![synced.clone(), native.clone()]);
        let mut updated = native.clone();
        updated.username = "Updated".into();
        merge_native_inventory(&mut vault, vec![updated.clone()])?;
        assert_eq!(vault.passkeys, vec![synced.clone(), updated]);
        let mut changed = native.clone();
        changed.credential_id = "Aw".into();
        assert!(merge_native_inventory(&mut vault, vec![changed]).is_err());
        let mut colliding = native.clone();
        colliding.id = synced.id.clone();
        assert!(merge_native_inventory(&mut vault, vec![colliding]).is_err());
        assert!(merge_native_inventory(&mut vault, vec![native.clone(), native]).is_err());
        Ok(())
    }

    #[test]
    fn trust_repair_is_an_explicit_join_option() -> Result<()> {
        for args in [
            vec!["keychain", "join"],
            vec!["keychain", "join", "--repair", "--bottle", "test-bottle"],
        ] {
            let cli = Cli::try_parse_from(&args).map_err(|e| Error::Config(e.to_string()))?;
            let Command::Join { repair, bottle } = cli.command else {
                panic!("expected join")
            };
            assert_eq!(repair, args.contains(&"--repair"));
            assert_eq!(bottle.is_some(), repair);
        }
        Ok(())
    }

    #[test]
    fn logout_removes_pending_repair_and_retained_peer_keys() -> Result<()> {
        use keychain::model::MobileMeState;
        use keychain::recovery::TrustRepair;
        let directory = tempfile::tempdir().map_err(|e| Error::io("fixture", e))?;
        let paths = AppPaths::new(
            directory.path().join("config"),
            directory.path().join("state"),
            directory.path().join("runtime"),
        )?;
        let backend = SoftwareFileBackend::new(paths.clone());
        let store = StateStore::new(&paths, &backend);
        let account = AccountState {
            schema_version: 1,
            username: "test@example.com".into(),
            adsid: "test".into(),
            logged_in_at: 1,
            mobileme: MobileMeState::default(),
            webservices: BTreeMap::new(),
        };
        let device = DeviceIdentity {
            schema_version: 1,
            device_id: "test".into(),
            serial: "test".into(),
            local_user_uuid: "test".into(),
        };
        let (mut original, _) = octagon::ensure_peer_identity(None, &account, &device, &backend)?;
        original.trust_state = OctagonTrustState::Joined;
        store.save_octagon(&original)?;
        let repair = TrustRepair::prepare(&store, &account, &device, &backend)?;
        let replacement = repair.candidate().clone();
        command_logout(false, &paths, &Config::default(), &backend, &store)?;
        assert!(!paths.trust_repair_file().exists());
        assert!(!paths.octagon_file().exists());
        assert!(backend.public_spki(&original.signing_key).is_err());
        assert!(backend.public_x963(&original.encryption_key).is_err());
        assert!(backend.public_spki(&replacement.signing_key).is_err());
        assert!(backend.public_x963(&replacement.encryption_key).is_err());
        assert!(paths.software_key_file().exists());
        Ok(())
    }

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

        command_logout(true, &paths, &Config::default(), &backend, &store)
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

    #[test]
    fn show_accepts_json_output() {
        let cli = Cli::try_parse_from(["keychain", "show", "record-id", "--json"])
            .unwrap_or_else(|error| panic!("parse show: {error}"));

        match cli.command {
            Command::Show { id, json } => {
                assert_eq!(id, "record-id");
                assert!(json);
            }
            command => panic!("expected show command, got {command:?}"),
        }
    }

    #[test]
    fn general_list_owns_inventory_and_passkey_has_no_list_subcommand() {
        let cli = Cli::try_parse_from(["keychain", "list", "webauthn.io", "--json"])
            .unwrap_or_else(|error| panic!("parse list: {error}"));
        match cli.command {
            Command::List { query, json } => {
                assert_eq!(query.as_deref(), Some("webauthn.io"));
                assert!(json);
            }
            command => panic!("expected list command, got {command:?}"),
        }
        assert!(Cli::try_parse_from(["keychain", "passkey", "list"]).is_err());
    }
}
