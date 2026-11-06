use crate::{Error, Result};
use std::{collections::HashMap, future::Future, time::Duration};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{OwnedObjectPath, OwnedValue},
};

pub struct ActiveSession {
    connection: Connection,
    path: OwnedObjectPath,
    owner: u32,
    id: String,
}

impl ActiveSession {
    pub fn for_owner(owner: u32) -> Result<Self> {
        let connection = Connection::system().map_err(failed)?;
        let manager = Proxy::new(
            &connection,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .map_err(failed)?;
        let user_path: OwnedObjectPath = manager.call("GetUser", &(owner,)).map_err(failed)?;
        let user = Proxy::new(
            &connection,
            "org.freedesktop.login1",
            user_path,
            "org.freedesktop.login1.User",
        )
        .map_err(failed)?;
        let (id, path): (String, OwnedObjectPath) = user.get_property("Display").map_err(failed)?;
        if id.is_empty() {
            return Err(Error::Refused("no active desktop session".into()));
        }
        let sessions: Vec<(String, OwnedObjectPath)> =
            user.get_property("Sessions").map_err(failed)?;
        let mut graphical = Vec::new();
        for (candidate, path) in sessions {
            let session = Proxy::new(
                &connection,
                "org.freedesktop.login1",
                path,
                "org.freedesktop.login1.Session",
            )
            .map_err(failed)?;
            let kind: String = session.get_property("Type").map_err(failed)?;
            if matches!(kind.as_str(), "wayland" | "x11") {
                graphical.push(candidate);
            }
        }
        if graphical != vec![id.clone()] {
            return Err(Error::Refused(
                "multiple graphical sessions for one UID are not supported by this prompt agent"
                    .into(),
            ));
        }
        drop(user);
        drop(manager);
        let session = Self {
            connection,
            path,
            owner,
            id,
        };
        if !session.valid() {
            return Err(Error::Refused(
                "desktop session is locked, remote or inactive".into(),
            ));
        }
        Ok(session)
    }

    pub fn valid(&self) -> bool {
        // One uncached GetAll snapshot, with a bound on the entire request.
        // No blocking property calls or stale success cache while a scalar lives.
        bounded_check(
            async {
                let query = self
                    .connection
                    .inner()
                    .call_method(
                        Some("org.freedesktop.login1"),
                        self.path.as_str(),
                        Some("org.freedesktop.DBus.Properties"),
                        "GetAll",
                        &("org.freedesktop.login1.Session",),
                    )
                    .await;
                let Ok(reply) = query else {
                    return false;
                };
                let Ok(properties) = reply.body().deserialize::<HashMap<String, OwnedValue>>()
                else {
                    return false;
                };
                matches_session(properties, self.owner, &self.id)
            },
            Duration::from_millis(250),
        )
    }
}

fn bounded_check(query: impl Future<Output = bool>, timeout: Duration) -> bool {
    async_io::block_on(futures_lite::future::or(query, async {
        async_io::Timer::after(timeout).await;
        false
    }))
}
fn matches_session(mut properties: HashMap<String, OwnedValue>, owner: u32, id: &str) -> bool {
    let boolean = |name: &str| {
        properties
            .get(name)
            .and_then(|value| bool::try_from(value).ok())
    };
    if boolean("Active") != Some(true)
        || boolean("Remote") != Some(false)
        || boolean("LockedHint") != Some(false)
    {
        return false;
    }
    let actual_id = properties
        .get("Id")
        .and_then(|value| <&str>::try_from(value).ok());
    let kind = properties
        .get("Type")
        .and_then(|value| <&str>::try_from(value).ok());
    if actual_id != Some(id) || !matches!(kind, Some("wayland" | "x11")) {
        return false;
    }
    properties
        .remove("User")
        .and_then(|value| <(u32, OwnedObjectPath)>::try_from(value).ok())
        .is_some_and(|(uid, _)| uid == owner)
}
fn failed(error: zbus::Error) -> Error {
    Error::Security(format!("cannot establish desktop session: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use zbus::zvariant::{Str, Value};

    fn properties() -> HashMap<String, OwnedValue> {
        let path = OwnedObjectPath::try_from("/org/freedesktop/login1/user/_1001")
            .unwrap_or_else(|e| panic!("test path: {e}"));
        HashMap::from([
            ("Active".into(), true.into()),
            ("Remote".into(), false.into()),
            ("LockedHint".into(), false.into()),
            ("Id".into(), Str::from("test-session").into()),
            ("Type".into(), Str::from("wayland").into()),
            (
                "User".into(),
                OwnedValue::try_from(Value::from((1001u32, path)))
                    .unwrap_or_else(|e| panic!("test user: {e}")),
            ),
        ])
    }

    #[test]
    fn session_snapshot_requires_complete_correctly_typed_local_unlocked_identity() {
        assert!(matches_session(properties(), 1001, "test-session"));
        assert!(!matches_session(properties(), 1002, "test-session"));
        assert!(!matches_session(properties(), 1001, "different-session"));
        for field in ["Active", "Remote", "LockedHint", "Id", "Type", "User"] {
            let mut props = properties();
            props.remove(field);
            assert!(!matches_session(props, 1001, "test-session"));
            let mut props = properties();
            props.insert(field.into(), 1u32.into());
            assert!(!matches_session(props, 1001, "test-session"));
        }
        for (field, value) in [("Active", false), ("Remote", true), ("LockedHint", true)] {
            let mut props = properties();
            props.insert(field.into(), value.into());
            assert!(!matches_session(props, 1001, "test-session"));
        }
        let mut props = properties();
        props.insert("Type".into(), Str::from("tty").into());
        assert!(!matches_session(props, 1001, "test-session"));
    }

    #[test]
    fn unresponsive_session_query_times_out_false_and_is_dropped() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let query = async {
            let _drop = Dropped(dropped.clone());
            std::future::pending::<()>().await;
            true
        };
        let start = std::time::Instant::now();
        assert!(!bounded_check(query, Duration::from_millis(10)));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(dropped.load(Ordering::Acquire));
        assert!(bounded_check(async { true }, Duration::from_millis(10)));
    }
}
