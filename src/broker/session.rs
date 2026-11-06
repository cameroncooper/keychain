use crate::{Error, Result};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::OwnedObjectPath,
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
        (|| -> zbus::Result<bool> {
            let session = Proxy::new(
                &self.connection,
                "org.freedesktop.login1",
                self.path.clone(),
                "org.freedesktop.login1.Session",
            )?;
            let active: bool = session.get_property("Active")?;
            let remote: bool = session.get_property("Remote")?;
            let locked: bool = session.get_property("LockedHint")?;
            let (owner, _): (u32, OwnedObjectPath) = session.get_property("User")?;
            let id: String = session.get_property("Id")?;
            let kind: String = session.get_property("Type")?;
            Ok(active
                && !remote
                && !locked
                && owner == self.owner
                && id == self.id
                && matches!(kind.as_str(), "wayland" | "x11"))
        })()
        .unwrap_or(false)
    }
}
fn failed(error: zbus::Error) -> Error {
    Error::Security(format!("cannot establish desktop session: {error}"))
}
