//! Durable sync update preparation. No biometric operation runs during sync.
//! The exact pending version is committed by the next explicit reveal/protect.
use super::*;

fn state(
    journal: &Journal,
    call: &mut impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<LoginState> {
    let state: LoginState = serde_json::from_value(call(Operation::LoginProtectionState {
        record: journal.source.id.clone(),
    })?)?;
    for summary in [&state.active, &state.staged].into_iter().flatten() {
        if !journal.recognizes(summary) {
            return Err(Error::Refused(
                "broker login is outside the frozen recovery history".into(),
            ));
        }
    }
    if state.active.as_ref().is_some_and(|active| !active.verified)
        || state
            .staged
            .as_ref()
            .is_some_and(|pending| pending.verified)
    {
        return Err(Error::Security("invalid login verification state".into()));
    }
    if let Some(pending) = &state.staged {
        if let Some(active) = &state.active {
            let cleanup = pending.revision == active.revision
                && pending.content_binding == active.content_binding
                && pending.metadata == active.metadata;
            if !cleanup && active.revision.checked_add(1) != Some(pending.revision) {
                return Err(Error::Refused(
                    "staged login has no matching verified predecessor".into(),
                ));
            }
        } else if !journal.history.is_empty() || pending.revision != 1 {
            return Err(Error::Refused(
                "verified login predecessor is missing".into(),
            ));
        }
    }
    Ok(state)
}
fn load(
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    id: &str,
    owner: u32,
    fingerprint: &str,
    socket: &Path,
) -> Result<Journal> {
    let file = path(paths, id)?;
    let sealed = read_bounded(&file)?;
    if sealed.len() > 4 * 1024 * 1024 {
        return Err(Error::InvalidData(
            "login recovery history exceeds limit".into(),
        ));
    }
    let plain = backend.open(Purpose::ProtectionMigration, &sealed)?;
    let journal: Journal = serde_json::from_slice(&plain)?;
    journal.validate()?;
    if journal.owner != owner
        || journal.account_fingerprint != fingerprint
        || journal.socket != socket
        || journal.source.id != id
    {
        return Err(Error::Security(
            "login recovery journal identity mismatch".into(),
        ));
    }
    Ok(journal)
}

/// State discovery precedes a single local publication attempt. A lost reply
/// leaves Prepared; an acknowledged missing stage never causes recreation.
pub(super) fn ensure_staged(
    journal: &mut Journal,
    file: &Path,
    backend: &dyn SecurityBackend,
    route: Option<&LoginRoute>,
    call: &mut impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<bool> {
    let before = state(journal, call)?;
    if before
        .active
        .as_ref()
        .is_some_and(|active| journal.current_matches(active))
    {
        if before
            .staged
            .as_ref()
            .is_some_and(|pending| !journal.current_matches(pending))
        {
            return Err(Error::Refused(
                "another staged version is still pending".into(),
            ));
        }
        journal.phase = Phase::BrokerVerified;
        save(file, backend, journal)?;
        return Ok(true);
    }
    if before
        .staged
        .as_ref()
        .is_some_and(|pending| journal.current_matches(pending))
    {
        journal.phase = Phase::Staged;
        save(file, backend, journal)?;
        return Ok(false);
    }
    if journal.phase != Phase::Prepared {
        return Err(Error::Refused(
            "acknowledged login version is missing; refusing replacement".into(),
        ));
    }
    if let Some(active) = &before.active {
        if active.revision != journal.prepared.expected_revision {
            return Err(Error::Refused(
                "login predecessor changed; sync again before verification".into(),
            ));
        }
    } else if !journal.history.is_empty()
        || journal.prepared.expected_revision != 0
        || route.is_some()
    {
        return Err(Error::Refused(
            "verified login predecessor is missing; refusing replacement".into(),
        ));
    }
    let operation = if let Some(pending) = before.staged {
        Operation::ReplaceStagedLogin {
            expected_content: pending.content_binding,
            import: Box::new(journal.prepared.clone()),
        }
    } else {
        Operation::ImportLogin {
            import: Box::new(journal.prepared.clone()),
        }
    };
    // This is local, revision-checked ciphertext publication, never a SEP/Apple
    // retry. Do not resend within this invocation after any transport error.
    call(operation)?;
    let after = state(journal, call)?;
    let verified = after
        .active
        .as_ref()
        .is_some_and(|active| journal.current_matches(active));
    if !verified
        && !after
            .staged
            .as_ref()
            .is_some_and(|pending| journal.current_matches(pending))
    {
        return Err(Error::Security(
            "broker did not retain the frozen login version".into(),
        ));
    }
    journal.phase = if verified {
        Phase::BrokerVerified
    } else {
        Phase::Staged
    };
    save(file, backend, journal)?;
    Ok(verified)
}
fn prepare(
    journal: &mut Journal,
    source: Credential,
    active: &LoginSummary,
    backend: &dyn SecurityBackend,
    file: &Path,
    call: &mut impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<()> {
    if journal.history.len() >= 64 {
        return Err(Error::Refused(
            "login recovery history is full; existing versions retained".into(),
        ));
    }
    if source.modified_at < journal.source.modified_at {
        return Err(Error::Refused(
            "stale login snapshot; existing versions retained".into(),
        ));
    }
    let recipient: Recipient = serde_json::from_value(call(Operation::ItemRecipient)?)?;
    if recipient.id != journal.prepared.recipient_id {
        return Err(Error::Refused(
            "login recipient changed; refusing re-keying".into(),
        ));
    }
    let prepared = LoginImport::seal(journal.owner, &recipient, active.revision, &source)?;
    let previous = Version {
        verified: journal.current_matches(active)
            || matches!(journal.phase, Phase::BrokerVerified | Phase::Committed),
        source: std::mem::replace(&mut journal.source, source),
        prepared: std::mem::replace(&mut journal.prepared, prepared),
    };
    journal.history.push(previous);
    journal.phase = Phase::Prepared;
    save(file, backend, journal)
}

pub(super) fn reconcile(
    incoming: Vec<Credential>,
    config: &Config,
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    fingerprint: &str,
    call: impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<(Vec<Credential>, Vec<String>)> {
    reconcile_as(
        incoming,
        config,
        paths,
        backend,
        SourceIdentity {
            owner: keychain_sep_driver::peer::effective_uid(),
            fingerprint,
        },
        call,
    )
}
fn reconcile_as(
    incoming: Vec<Credential>,
    config: &Config,
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    identity: SourceIdentity<'_>,
    mut call: impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<(Vec<Credential>, Vec<String>)> {
    let socket = config
        .credential_broker
        .as_ref()
        .ok_or_else(|| Error::Config("protected logins require their broker".into()))?;
    let mut next = config.clone();
    let mut result = Vec::new();
    let mut ids = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for source in incoming {
        if !seen.insert(source.id.clone()) {
            return Err(Error::InvalidData("duplicate synced login record".into()));
        }
        let Some(route) = config
            .protected_logins
            .iter()
            .find(|route| route.id == source.id)
        else {
            result.push(source);
            continue;
        };
        if route.account_fingerprint != identity.fingerprint {
            return Err(Error::Refused(
                "synced login belongs to another protected account".into(),
            ));
        }
        let mut journal = load(
            paths,
            backend,
            &source.id,
            identity.owner,
            identity.fingerprint,
            socket,
        )?;
        journal.check_route(route)?;
        let before = state(&journal, &mut call)?;
        let active = before.active.as_ref().ok_or_else(|| {
            Error::Refused(
                "verified login predecessor is missing; refusing software fallback".into(),
            )
        })?;
        // Refuse known rollback or disappearance of a published route. A lost
        // replacement reply is recoverable only when the exact newer frozen
        // payload is already present at the root service.
        let current_route = journal.route()?;
        let route_verified = (current_route == *route
            && matches!(journal.phase, Phase::BrokerVerified | Phase::Committed))
            || journal.history.iter().any(|version| {
                version.verified && version.prepared.content_binding == route.content_binding
            });
        let route_present = route.matches(active)
            || before
                .staged
                .as_ref()
                .is_some_and(|pending| route.identifies(pending));
        let current_present = journal.current_matches(active)
            || before
                .staged
                .as_ref()
                .is_some_and(|pending| journal.current_matches(pending));
        if (route_verified
            && (active.revision < route.revision
                || (active.revision == route.revision && !route.matches(active))))
            || (!route_present && !current_present)
        {
            return Err(Error::Refused(
                "published login version is missing or rolled back".into(),
            ));
        }
        let file = path(paths, &source.id)?;
        for version in &mut journal.history {
            if version_matches(&version.source, &version.prepared, active) {
                version.verified = true;
            }
        }

        let needs_rebase = source == journal.source
            && !journal.current_matches(active)
            && active.revision != journal.prepared.expected_revision;
        if needs_rebase
            && (journal.phase != Phase::Prepared
                || !route.matches(active)
                || before
                    .staged
                    .as_ref()
                    .is_some_and(|pending| journal.current_matches(pending)))
        {
            return Err(Error::Refused(
                "published login predecessor changed; refusing replacement".into(),
            ));
        }
        if source != journal.source || needs_rebase {
            prepare(&mut journal, source, active, backend, &file, &mut call)?;
        }
        ensure_staged(&mut journal, &file, backend, Some(route), &mut call)?;
        let new_route = journal.route()?;
        let slot = next
            .protected_logins
            .iter_mut()
            .find(|route| route.id == journal.source.id)
            .ok_or_else(|| Error::Security("login route disappeared".into()))?;
        *slot = new_route;
        // An acknowledged encrypted stage is durable before routing is published;
        // lookup can select it without ever reading this secret-bearing journal.
        next.save(paths)?;
        ids.push(journal.source.id.clone());
        result.push(redacted(&journal.source));
    }
    Ok((result, ids))
}

pub(super) fn inventory(
    config: &Config,
    summaries: Vec<LoginSummary>,
    mut state: impl FnMut(&str) -> Result<LoginState>,
) -> Result<Vec<LoginSummary>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut visible = Vec::new();
    for summary in summaries {
        if !seen.insert(summary.metadata.id.clone()) {
            return Err(Error::Security("duplicate broker login".into()));
        }
        let Some(route) = config
            .protected_logins
            .iter()
            .find(|route| route.id == summary.metadata.id)
        else {
            continue;
        };
        if route.matches(&summary) {
            visible.push(summary);
            continue;
        }
        let state = state(&summary.metadata.id)?;
        let active = state
            .active
            .ok_or_else(|| Error::Refused("protected login predecessor disappeared".into()))?;
        let pending = state.staged.ok_or_else(|| {
            Error::Refused("selected protected login is missing; refusing software fallback".into())
        })?;
        if !active.verified
            || !route.identifies(&pending)
            || pending.verified
            || active.revision.checked_add(1) != Some(pending.revision)
            || active.recipient_id != pending.recipient_id
            || active.content_binding != summary.content_binding
            || active.revision != summary.revision
        {
            return Err(Error::Refused(
                "selected protected login changed; refusing software fallback".into(),
            ));
        }
        visible.push(pending);
    }
    Ok(visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VaultState;
    use crate::protection::login::tests::{Fixture, Remote};
    use crate::security::sep::ProviderError;

    fn changed(f: &Fixture, revision: u64) -> Credential {
        let mut source = f.source.clone();
        source.password = format!("synthetic revision {revision}");
        source.modified_at = revision as f64 + 2.0;
        source.title = format!("Synthetic update {revision}");
        source
    }
    fn sync(
        f: &Fixture,
        remote: &mut Remote,
        incoming: Vec<Credential>,
    ) -> Result<Vec<Credential>> {
        let config = Config::load(&f.paths)?;
        let (items, _) = reconcile_as(
            incoming,
            &config,
            &f.paths,
            &f.backend,
            SourceIdentity {
                owner: 1001,
                fingerprint: &f.fingerprint,
            },
            |op| remote.call(op),
        )?;
        StateStore::new(&f.paths, &f.backend).save_vault(&VaultState {
            schema_version: 1,
            synced_at: 2,
            credentials: items.clone(),
            passkeys: vec![],
        })?;
        Ok(items)
    }
    fn fixture() -> Result<(Fixture, Remote)> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        f.run(&mut remote)?;
        Ok((f, remote))
    }
    #[test]
    fn changed_sync_stages_without_capture_and_protect_commits_exact_latest_source() -> Result<()> {
        let (f, mut remote) = fixture()?;
        let source = changed(&f, 2);
        let items = sync(&f, &mut remote, vec![source.clone()])?;
        assert!(items[0].protected && items[0].password.is_empty() && items[0].totp_uri.is_empty());
        assert_eq!(remote.verifies, 1);
        assert_eq!(
            remote.state.active.as_ref().map(|record| record.revision),
            Some(1)
        );
        assert_eq!(
            remote.state.staged.as_ref().map(|record| record.revision),
            Some(2)
        );
        let config = Config::load(&f.paths)?;
        assert_eq!(config.protected_logins[0].revision, 2);
        let visible = inventory(
            &config,
            vec![
                remote
                    .state
                    .active
                    .clone()
                    .ok_or_else(|| Error::Security("test active".into()))?,
            ],
            |_| Ok(remote.state.clone()),
        )?;
        assert_eq!(visible.len(), 1);
        assert!(!visible[0].verified);
        assert_eq!(visible[0].metadata.title, source.title);
        assert!(f.journal()?.phase == Phase::Staged);
        assert_eq!(f.journal()?.history[0].source, f.source);
        f.run(&mut remote)?;
        assert_eq!(remote.verifies, 2);
        assert_eq!(
            remote.state.active.as_ref().map(|record| record.revision),
            Some(2)
        );
        assert!(remote.state.staged.is_none());
        assert!(f.journal()?.phase == Phase::Committed);
        assert_eq!(f.journal()?.source, source);
        assert_eq!(f.journal()?.history[0].source, f.source);
        let count = remote.imports;
        sync(&f, &mut remote, vec![source])?;
        assert_eq!(remote.imports, count);
        Ok(())
    }
    #[test]
    fn repeated_cloud_changes_replace_only_the_exact_pending_version_and_keep_recovery_history()
    -> Result<()> {
        let (f, mut remote) = fixture()?;
        sync(&f, &mut remote, vec![changed(&f, 2)])?;
        let first = remote
            .state
            .staged
            .as_ref()
            .ok_or_else(|| Error::Security("test pending".into()))?
            .content_binding
            .clone();
        sync(&f, &mut remote, vec![changed(&f, 3)])?;
        let next = remote
            .state
            .staged
            .as_ref()
            .ok_or_else(|| Error::Security("test pending".into()))?;
        assert_ne!(next.content_binding, first);
        assert_eq!(next.revision, 2);
        assert_eq!(
            remote.state.active.as_ref().map(|record| record.revision),
            Some(1)
        );
        assert_eq!(remote.verifies, 1);
        assert_eq!(f.journal()?.history.len(), 2);
        assert!(
            f.journal()?
                .history
                .iter()
                .any(|version| version.prepared.content_binding == first)
        );
        f.run(&mut remote)?;
        assert_eq!(f.journal()?.source, changed(&f, 3));
        Ok(())
    }
    #[test]
    fn lost_staging_and_config_publication_resume_with_the_same_ciphertext() -> Result<()> {
        let (f, mut remote) = fixture()?;
        let source = changed(&f, 2);
        remote.lose_stage = true;
        assert!(sync(&f, &mut remote, vec![source.clone()]).is_err());
        let frozen = f.journal()?.prepared.content_binding;
        assert!(f.journal()?.phase == Phase::Prepared);
        assert_eq!(Config::load(&f.paths)?.protected_logins[0].revision, 1);
        let count = remote.imports;
        sync(&f, &mut remote, vec![source.clone()])?;
        assert_eq!(remote.imports, count);
        assert_eq!(f.journal()?.prepared.content_binding, frozen);
        // Fail routing publication after the root acknowledged an update.
        let old_config = Config::load(&f.paths)?;
        let source = changed(&f, 3);
        let mut injected = false;
        assert!(
            reconcile_as(
                vec![source.clone()],
                &old_config,
                &f.paths,
                &f.backend,
                SourceIdentity {
                    owner: 1001,
                    fingerprint: &f.fingerprint
                },
                |op| {
                    let publish = matches!(&op, Operation::ReplaceStagedLogin { .. });
                    let result = remote.call(op)?;
                    if publish && !injected {
                        injected = true;
                        std::fs::remove_file(f.paths.config_file())
                            .map_err(|e| Error::io("test config", e))?;
                        std::fs::create_dir(f.paths.config_file())
                            .map_err(|e| Error::io("test config", e))?;
                    }
                    Ok(result)
                }
            )
            .is_err()
        );
        let frozen = f.journal()?.prepared.content_binding;
        assert!(f.journal()?.phase == Phase::Staged);
        std::fs::remove_dir(f.paths.config_file()).map_err(|e| Error::io("test config", e))?;
        old_config.save(&f.paths)?;
        let count = remote.imports;
        sync(&f, &mut remote, vec![source])?;
        assert_eq!(remote.imports, count);
        assert_eq!(f.journal()?.prepared.content_binding, frozen);
        Ok(())
    }
    #[test]
    fn acknowledged_loss_unknown_data_rollback_and_wrong_account_never_recreate_state() -> Result<()>
    {
        let (f, mut remote) = fixture()?;
        let source = changed(&f, 2);
        sync(&f, &mut remote, vec![source.clone()])?;
        let pending = remote.state.staged.clone();
        remote.state.staged = None;
        let count = remote.imports;
        assert!(sync(&f, &mut remote, vec![source.clone()]).is_err());
        assert_eq!(remote.imports, count);
        remote.state.staged = pending;
        let previous = remote.state.active.clone();
        f.run(&mut remote)?;
        remote.state.active = previous;
        assert!(sync(&f, &mut remote, vec![changed(&f, 3)]).is_err());
        assert_eq!(remote.imports, count);
        let config = Config::load(&f.paths)?;
        assert!(
            reconcile_as(
                vec![source],
                &config,
                &f.paths,
                &f.backend,
                SourceIdentity {
                    owner: 1001,
                    fingerprint: "another-account"
                },
                |_| panic!("must refuse before lookup")
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn pending_commit_race_rebases_only_an_unpublished_plan_against_the_verified_predecessor()
    -> Result<()> {
        let (f, mut remote) = fixture()?;
        sync(&f, &mut remote, vec![changed(&f, 2)])?;
        let config = Config::load(&f.paths)?;
        let source = changed(&f, 3);
        let mut raced = false;
        assert!(
            reconcile_as(
                vec![source.clone()],
                &config,
                &f.paths,
                &f.backend,
                SourceIdentity {
                    owner: 1001,
                    fingerprint: &f.fingerprint
                },
                |op| {
                    if matches!(&op, Operation::ReplaceStagedLogin { .. }) && !raced {
                        raced = true;
                        let mut committed = remote
                            .state
                            .staged
                            .take()
                            .ok_or_else(|| Error::Security("test pending".into()))?;
                        committed.verified = true;
                        remote.state.active = Some(committed);
                        return Err(ProviderError::Busy.into());
                    }
                    remote.call(op)
                }
            )
            .is_err()
        );
        let unpublished = f.journal()?.prepared.content_binding;
        assert!(f.journal()?.phase == Phase::Prepared);
        sync(&f, &mut remote, vec![source.clone()])?;
        assert_eq!(
            remote.state.active.as_ref().map(|record| record.revision),
            Some(2)
        );
        assert_eq!(
            remote.state.staged.as_ref().map(|record| record.revision),
            Some(3)
        );
        assert!(
            f.journal()?
                .history
                .iter()
                .any(|version| version.prepared.content_binding == unpublished)
        );
        assert_ne!(f.journal()?.prepared.content_binding, unpublished);
        f.run(&mut remote)?;
        assert_eq!(f.journal()?.source, source);
        Ok(())
    }
    #[test]
    fn unchanged_deletion_and_history_limits_preserve_native_inventory_and_existing_data()
    -> Result<()> {
        let (f, mut remote) = fixture()?;
        let count = remote.imports;
        sync(&f, &mut remote, vec![f.source.clone()])?;
        assert_eq!(remote.imports, count);
        let config = Config::load(&f.paths)?;
        let (items, ids) = reconcile_as(
            vec![],
            &config,
            &f.paths,
            &f.backend,
            SourceIdentity {
                owner: 1001,
                fingerprint: &f.fingerprint,
            },
            |_| panic!("deleted record must not unseal"),
        )?;
        assert!(items.is_empty() && ids.is_empty());
        for version in 2..=65 {
            sync(&f, &mut remote, vec![changed(&f, version)])?;
        }
        assert_eq!(f.journal()?.history.len(), 64);
        let frozen = f.journal()?.prepared.content_binding;
        let count = remote.imports;
        assert!(sync(&f, &mut remote, vec![changed(&f, 66)]).is_err());
        assert_eq!(f.journal()?.prepared.content_binding, frozen);
        assert_eq!(remote.imports, count);
        assert_eq!(f.journal()?.history[0].source, f.source);
        Ok(())
    }
}
