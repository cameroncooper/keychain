//! Real private-bus tests. The bus has no activation/service directories, so
//! these fixtures cannot start the installed agent or access the real session.
use super::*;
use futures_lite::StreamExt;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};
struct PrivateBus {
    child: Child,
    _directory: tempfile::TempDir,
    address: String,
}
impl PrivateBus {
    fn start() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let config = directory.path().join("bus.conf");
        std::fs::write(
            &config,
            r#"<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>"#,
        )?;
        let mut child = Command::new("dbus-daemon")
            .arg("--nofork")
            .arg("--print-address=1")
            .arg("--config-file")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut address = String::new();
        let result = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing bus output"))
            .and_then(|output| BufReader::new(output).read_line(&mut address));
        if result.is_err() || address.trim().is_empty() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("private bus failed"));
        }
        Ok(Self {
            child,
            _directory: directory,
            address: address.trim().to_owned(),
        })
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> io::Result<T> {
    futures_lite::future::or(async { Ok(future.await) }, async {
        async_io::Timer::after(Duration::from_secs(3)).await;
        Err(io::Error::other("D-Bus fixture timed out"))
    })
    .await
}
#[test]
fn actual_dbus_introspection_property_changes_and_cancel_contract() -> io::Result<()> {
    let private = PrivateBus::start()?;
    let (publication, publications) = Publication::new();
    let (commands, receiver) = mpsc::sync_channel(4);
    async_io::block_on(async {
        let service = zbus::connection::Builder::address(private.address.as_str())
            .map_err(io_error)?
            .serve_at(PATH, publication.interface(commands))
            .map_err(io_error)?
            .build()
            .await
            .map_err(io_error)?;
        let client = zbus::connection::Builder::address(private.address.as_str())
            .map_err(io_error)?
            .build()
            .await
            .map_err(io_error)?;
        // Export is usable via the unique name even before acquiring the public name.
        let unique = service
            .unique_name()
            .ok_or_else(|| io::Error::other("unique bus owner missing"))?
            .to_string();
        let reply = client
            .call_method(
                Some(unique.as_str()),
                PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(INTERFACE, "Snapshot"),
            )
            .await
            .map_err(io_error)?;
        assert_eq!(
            reply.body().signature().map(|s| s.to_string()).as_deref(),
            Some("v")
        );
        let value: zbus::zvariant::OwnedValue = reply.body().deserialize().map_err(io_error)?;
        let initial = String::try_from(value).map_err(io_error)?;
        assert_eq!(initial, r#"{"version":1,"generation":0,"request":null}"#);
        service
            .request_name_with_flags(
                crate::prompt::activation::AGENT_BUS_NAME,
                zbus::fdo::RequestNameFlags::DoNotQueue.into(),
            )
            .await
            .map_err(io_error)?;
        let proxy = zbus::Proxy::new(
            &client,
            crate::prompt::activation::AGENT_BUS_NAME,
            PATH,
            INTERFACE,
        )
        .await
        .map_err(io_error)?;
        let introspection = client
            .call_method(
                Some(crate::prompt::activation::AGENT_BUS_NAME),
                PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .map_err(io_error)?;
        let xml: String = introspection.body().deserialize().map_err(io_error)?;
        assert!(xml.contains("name=\"Snapshot\" type=\"s\" access=\"read\""));
        assert!(xml.contains("method name=\"Cancel\""));
        for forbidden in [
            "method name=\"Begin\"",
            "method name=\"Approve\"",
            "method name=\"Visible\"",
            "method name=\"Selected\"",
        ] {
            assert!(!xml.contains(forbidden));
        }
        let properties = zbus::Proxy::new(
            &client,
            crate::prompt::activation::AGENT_BUS_NAME,
            PATH,
            "org.freedesktop.DBus.Properties",
        )
        .await
        .map_err(io_error)?;
        let mut signals = properties
            .receive_signal("PropertiesChanged")
            .await
            .map_err(io_error)?;
        publications.run(service.clone());
        let key = RequestKey {
            id: Uuid::new_v4(),
            connection: Uuid::new_v4(),
        };
        let presentation =
            Presentation::diagnostic(key.id, PromptOperation::DiagnosticCancel, "not exported");
        publication.begin(key, &presentation, false, Deadline(None))?;
        publication.visible(key)?;
        publication.status(
            key,
            PromptPhase::DiagnosticCancel,
            Deadline(Some(12345)),
            "Do not touch",
        )?;
        let target_generation = publication
            .state
            .lock()
            .map_err(io_error)?
            .snapshot
            .generation;
        let mut previous = 0;
        loop {
            let message = bounded(signals.next())
                .await?
                .ok_or_else(|| io::Error::other("signal stream ended"))?;
            assert_eq!(
                message.body().signature().map(|s| s.to_string()).as_deref(),
                Some("sa{sv}as")
            );
            let (interface, mut changed, invalidated): (
                String,
                std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
                Vec<String>,
            ) = message.body().deserialize().map_err(io_error)?;
            assert_eq!(interface, INTERFACE);
            assert!(invalidated.is_empty());
            let json = String::try_from(
                changed
                    .remove("Snapshot")
                    .ok_or_else(|| io::Error::other("missing full snapshot"))?,
            )
            .map_err(io_error)?;
            let snapshot: serde_json::Value = serde_json::from_str(&json).map_err(io_error)?;
            let generation = snapshot["generation"]
                .as_u64()
                .ok_or_else(|| io::Error::other("bad generation"))?;
            assert!(generation > previous);
            previous = generation;
            if generation == target_generation {
                assert_eq!(snapshot["request"]["phase"], "diagnostic-cancel");
                break;
            }
        }
        let read: String = proxy.get_property("Snapshot").await.map_err(io_error)?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read).map_err(io_error)?["generation"],
            target_generation
        );
        let invalid: Result<(), zbus::Error> = proxy.call("Cancel", &("invalid",)).await;
        assert!(
            matches!(invalid,Err(zbus::Error::MethodError(name,_,_)) if name.as_str()=="org.freedesktop.DBus.Error.InvalidArgs")
        );
        let cloned = publication.clone();
        let ui = std::thread::spawn(move || -> io::Result<()> {
            let command = receiver
                .recv_timeout(Duration::from_secs(2))
                .map_err(io_error)?;
            assert_eq!(command.key, key);
            cloned.retire(key)?;
            command.applied();
            Ok(())
        });
        let canceled = proxy
            .call_method("Cancel", &(key.id.to_string(),))
            .await
            .map_err(io_error)?;
        assert!(canceled.body().is_empty());
        ui.join()
            .map_err(|_| io::Error::other("UI fixture failed"))??;
        proxy
            .call::<_, _, ()>("Cancel", &(key.id.to_string(),))
            .await
            .map_err(io_error)?;
        let read: String = proxy.get_property("Snapshot").await.map_err(io_error)?;
        assert!(
            serde_json::from_str::<serde_json::Value>(&read).map_err(io_error)?["request"]
                .is_null()
        );
        // An owner replacement is a new generation epoch, not a continuation.
        service
            .release_name(crate::prompt::activation::AGENT_BUS_NAME)
            .await
            .map_err(io_error)?;
        let (replacement, _) = Publication::new();
        let (commands, _) = mpsc::sync_channel(1);
        let second = zbus::connection::Builder::address(private.address.as_str())
            .map_err(io_error)?
            .serve_at(PATH, replacement.interface(commands))
            .map_err(io_error)?
            .build()
            .await
            .map_err(io_error)?;
        second
            .request_name(crate::prompt::activation::AGENT_BUS_NAME)
            .await
            .map_err(io_error)?;
        assert_ne!(service.unique_name(), second.unique_name());
        let response = client
            .call_method(
                Some(crate::prompt::activation::AGENT_BUS_NAME),
                PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(INTERFACE, "Snapshot"),
            )
            .await
            .map_err(io_error)?;
        let value: zbus::zvariant::OwnedValue = response.body().deserialize().map_err(io_error)?;
        assert_eq!(String::try_from(value).map_err(io_error)?, initial);
        drop(publication);
        Ok(())
    })
}
