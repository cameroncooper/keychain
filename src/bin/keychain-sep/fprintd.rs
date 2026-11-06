//! Disposable integration check using fprintd's standard Claim/Release API.
//! Never enrolls, deletes, restarts fprintd, or releases another client's claim.
use keychain::broker::{Operation, call};
use std::path::PathBuf;
use std::time::Duration;

struct Claim<'a> {
    device: zbus::blocking::Proxy<'a>,
    held: bool,
}
impl Claim<'_> {
    fn release(&mut self) -> zbus::Result<()> {
        if self.held {
            self.device.call::<_, _, ()>("Release", &())?;
            self.held = false;
        }
        Ok(())
    }
}
impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

pub fn check(record: String, socket: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if keychain_sep_driver::peer::effective_uid() == 0 {
        return Err("run coexistence checks as the paired unprivileged user".into());
    }
    let metadata = call(
        &socket,
        Operation::InspectProtected {
            record: record.clone(),
        },
    )?;
    if metadata["verified"] != true
        || metadata["credential"]["rp_id"] != "diagnostic.invalid"
        || metadata["credential"]["username"] != "Synthetic migration check"
    {
        return Err("coexistence diagnostic requires the disposable migrated fixture".into());
    }
    let connection = zbus::blocking::Connection::system()?;
    let manager = zbus::blocking::Proxy::new(
        &connection,
        "net.reactivated.Fprint",
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
    )?;
    let path: zbus::zvariant::OwnedObjectPath = manager.call("GetDefaultDevice", &())?;
    let device = zbus::blocking::Proxy::new(
        &connection,
        "net.reactivated.Fprint",
        path.as_str(),
        "net.reactivated.Fprint.Device",
    )?;
    device.call::<_, _, ()>("Claim", &("",))?;
    let mut claim = Claim { device, held: true };
    let status = call(&socket, Operation::Status)?;
    if status["sepDevice"] != "busy" {
        return Err(
            "fprintd claim did not exclusively hold the SEP device; no coexistence result claimed"
                .into(),
        );
    }
    println!("fprintd owns the device; do not touch until the desktop asks after release");
    let operation_socket = socket.clone();
    let worker =
        std::thread::spawn(move || call(&operation_socket, Operation::VerifyProtected { record }));
    std::thread::sleep(Duration::from_secs(3));
    let completed_while_claimed = worker.is_finished();
    let release = claim.release();
    // Join even on release failure so the single request resolves under its
    // original deadline. Never replay its command after ambiguous completion.
    if release.is_ok() {
        println!("fprintd claim released; touch when the desktop asks");
    } else {
        eprintln!(
            "fprintd release failed; waiting for the pending request to resolve without retry"
        );
    }
    let outcome = worker
        .join()
        .map_err(|_| "broker diagnostic worker failed")?;
    release?;
    if completed_while_claimed {
        return Err("broker completed before fprintd released the device".into());
    }
    let outcome = outcome?;
    if outcome["verified"] != true {
        return Err("broker did not verify the selected operation".into());
    }
    if call(&socket, Operation::Status)?["sepDevice"] != "available" {
        return Err("device unavailable after the completed operation".into());
    }
    println!(
        "verified fprintd claim -> broker wait -> release -> biometric operation -> device available"
    );
    Ok(())
}
