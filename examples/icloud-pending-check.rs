//! Root-only, read-only comparison of an existing pending upload with CloudKit.
//! No save, key creation, SEP unsealing or reader capture. Optional reconciliation
//! verifies downloaded ciphertext and checkpoints only the existing local journal.
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use keychain::apple::ckks::upload::{Phase, SaveOutcome, Snapshot, UploadIo};
use keychain::apple::ckks::{Record, ZoneIdentity};
use keychain::apple::worker::WorkerClient;
use keychain::broker::registry::Registry;
use keychain::{Error, Result};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    registry: PathBuf,
    #[arg(long)]
    owner: u32,
    #[arg(long)]
    record: Uuid,
    /// Verify the existing cloud ciphertext and checkpoint it locally; never sends a save.
    #[arg(long)]
    reconcile: bool,
}

struct NoSave<'a>(&'a mut dyn UploadIo);
impl UploadIo for NoSave<'_> {
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot> {
        self.0.fetch_zone(zone, check)
    }
    fn create_atomic(
        &mut self,
        _: Uuid,
        _: &ZoneIdentity,
        _: &Record,
        _: &Record,
        _: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome> {
        Err(Error::Refused(
            "pending inspection cannot send a save".into(),
        ))
    }
}

fn run() -> Result<()> {
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("process protection", e))?;
    if keychain_sep_driver::peer::effective_uid() != 0 {
        return Err(Error::Refused(
            "administrator inspection requires root".into(),
        ));
    }
    let args = Args::parse();
    if !args.registry.is_absolute() || args.owner == 0 {
        return Err(Error::Refused("invalid diagnostic scope".into()));
    }
    for ancestor in args.registry.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).map_err(|e| Error::io(ancestor, e))?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(Error::Refused("unsafe diagnostic registry".into()));
        }
    }
    // Refuse missing roots before Registry::open can initialize anything.
    for file in [
        "state/software.key".to_owned(),
        format!("synced-create-{}.enc", args.record),
    ] {
        let path = args.registry.join(file);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| Error::io(&path, e))?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err(Error::Refused("unsafe or missing diagnostic input".into()));
        }
    }
    let registry = Registry::open(&args.registry)?;
    let draft = registry.load_synced_creation(&args.record.to_string(), args.owner)?;
    let binding = draft.binding().clone();
    let mut session = registry.uploads()?.resume(&binding)?;
    let public = STANDARD
        .decode(&draft.record().public_sec1)
        .map_err(|_| Error::Refused("invalid draft public key".into()))?;
    session.verify_identity(&binding, &draft.record().credential, &public)?;
    let phase = match session.phase()? {
        Phase::Prepared => "prepared",
        Phase::Attempted { .. } => "attempted/uncertain",
        Phase::Accepted { .. } => "accepted",
        Phase::FetchVerified { .. } => "fetch-verified",
        Phase::Rejected => "rejected",
    };
    println!("upload phase: {phase}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let check = || {
        if Instant::now() >= deadline {
            Err(Error::Refused("read-only inspection expired".into()))
        } else {
            Ok(())
        }
    };
    let account = registry.load_account(args.owner)?;
    let client = WorkerClient::connect(
        &account.worker().socket,
        account.worker().uid,
        binding.clone(),
        deadline,
        &check,
        &check,
    )?;
    let mut io = registry.account_upload_io(args.owner, client, &check)?;
    let snapshot = io.fetch_zone(&binding.zone, &check)?;
    println!(
        "{}",
        serde_json::to_string(&session.compare_snapshot(&snapshot)?)?
    );
    if args.reconcile {
        if !matches!(
            session.phase()?,
            Phase::Attempted { .. } | Phase::Accepted { .. } | Phase::FetchVerified { .. }
        ) {
            return Err(Error::Refused(
                "reconciliation requires an existing uncertain/accepted upload".into(),
            ));
        }
        session.advance(&mut NoSave(&mut io), &check)?;
        session.verified_upload()?;
        println!(
            "existing cloud record cryptographically verified; local journal checkpointed; no save or registration signature sent"
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pending-upload inspection: {error}");
        std::process::exit(1);
    }
}
