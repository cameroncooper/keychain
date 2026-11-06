# Broker account enrollment and authenticated roots

The broker can now enroll the existing Octagon agreement identity through an
explicit root-administrator pipe. This is not an owner/browser socket operation.
No account has been enrolled from the real profile during implementation, and no
Apple write, sign-in, escrow retry or biometric capture was used in these tests.

The two bootstrap packages have different recipients and contents:

| Recipient | Private material | Public scope |
| --- | --- | --- |
| Network service's encrypted systemd credential | CloudKit token and existing ADI seed | Owner, account/device/peer and zone |
| Privileged broker's encrypted local registry | Existing P-384 Octagon agreement key | Same owner/account/device/peer/zone plus worker UID/socket |

The broker package contains no CloudKit token, PET, ADI, vault or signing private
key. Export does not generate a peer or encryption root. Unsupported/nonexportable
backends refuse; the current implementation exports the existing software
account key. This is a software-protected account bootstrap, not SEP root
unsealing. The source account keys are retained. Existing account-root recovery
outside the broker is unchanged and belongs to the protected-root follow-up.

The package includes the existing signed permanent peer info. Both exporter and
importer recompute its peer hash, verify its P-384 signature, reject ambiguous
public-key fields, and require the supplied agreement scalar/public point to
match its signed agreement SPKI. Export also checks the stored signing public
key against the signed identity. The source must have the matching joined peer.
These checks pin a locally selected identity; they do not prove server trust or
fresh token acceptance without the subsequent authenticated fetch.

Enrollment freezes owner/account/peer/device/worker in an encrypted intent before
key import. A retry cannot replace that selection, including after loss of the
account metadata checkpoint. Importing an identical agreement key/usage reuses
the same local key reference after a partial persistence failure. Account and
intent metadata use the distinct BrokerAccount envelope purpose. Load verifies
the owner, intent, key policy, permanent signature and stored agreement public
key again. Lost metadata roots or committed intents refuse replacement. Account
metadata never appears in the browser credential inventory.

## Explicit administrative pipe

Complete fresh normal-profile authentication/trust repair before applying either
bootstrap package. Never save the broker export as plaintext or paste it in chat.
On this development machine the paired owner is 1001 and the installed network
service UID is 957; use your actual selected values elsewhere.

```sh
set -o pipefail
/usr/libexec/keychain/keychain-network-worker export --target broker |
  sudo -n /usr/libexec/keychain/keychain-broker \
    --registry /var/lib/keychain-broker/1001 --owner 1001 \
    import-account --worker-uid 957
```

Root authorization must already be available to the explicitly invoked command;
`-n` prevents reading a password through the private-data pipe. Both ends reject
terminals/regular files and require a FIFO owned by root or the selected owner,
with no group/other permissions. Input/output buffers are bounded and zeroizing. This command imports
only the existing key and metadata: no Apple request, new identity, biometric
capture or worker startup follows. The worker's separate credential/bootstrap
procedure is in [NETWORK-WORKER.md](../contrib/NETWORK-WORKER.md).

## Fetch verification

`Registry::account_upload_io` loads the validated account and connects it to an
already authenticated worker client. Scope must match exactly. The protocol has
one new read-only operation for recoverable shares; the concrete worker permits
only `fetchRecoverableTLKShares` with the canonical enrolled-peer request. It
returns raw Cuttlefish records, never plaintext roots or an authorization flag.

Before capture, the broker fetches recoverable shares and every page of the live
Passwords zone. It accepts self-shares only, checks the sender signature against
the pinned permanent signing key, checks the exact recipient point, and unwraps
using the imported agreement key. Live-only shares are supported. Conflicting
recoverable/live root material, unsupported classes, missing Passwords roots,
wrong signatures/recipients and cancellation fail closed. Cancellation checks
surround each share's cryptographic processing. No sponsor-key fallback exists.
Only then is a complete authenticated Snapshot constructed. Its first use by the
coordinator reuses that preflight snapshot; later verification fetches remain
independent. Roots never cross the worker protocol. A changed hierarchy can
require a new authorized recovery operation; it cannot cause automatic re-keying
or replay of an uncertain write.

Two offline tests cover selective export and malformed/changed key/signature
inputs; another checks that administrator transfers reject files and sockets and
accept a private pipe. A disposable root integration test covers immutable/idempotent enrollment,
partial checkpoint recovery, missing intent/root refusal, inventory separation,
signed live-only TLK unwrap, conflicting shares, cancellation, and raw worker
share/page framing through authenticated snapshot construction. It uses synthetic
keys and a fake pre-authenticated channel; real kernel UID checks and systemd
credential isolation are tested separately by the worker startup checks.

The typed broker worker-start/connect path and browser integration remain to be
connected. No production browser operation accepts bootstrap JSON, Snapshot or
VerifiedUpload as authorization. Live authentication, scoped Apple upload
acceptance/atomicity, real biometric creation and other-device validation remain
unproven. Do not enable the iCloud creation choice on the basis of these offline
tests alone.
