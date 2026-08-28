use std::collections::{HashMap, HashSet};

use elogind_usersv_core::account::Account;
use futures_util::StreamExt;
use tokio::sync::{mpsc, oneshot};
use zbus::{Connection, zvariant::OwnedObjectPath};

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Login1Manager {
    fn list_sessions(&self) -> zbus::Result<Vec<(String, u32, String, String, OwnedObjectPath)>>;
    fn get_session(&self, session_id: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_user(&self, uid: u32) -> zbus::Result<OwnedObjectPath>;

    #[zbus(signal)]
    fn session_new(&self, session_id: String, object_path: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    fn session_removed(&self, session_id: String, object_path: OwnedObjectPath)
    -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait Login1Session {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn user(&self) -> zbus::Result<(u32, OwnedObjectPath)>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn class(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn service(&self) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.User",
    default_service = "org.freedesktop.login1"
)]
trait Login1User {
    #[zbus(property)]
    fn runtime_path(&self) -> zbus::Result<String>;
}

#[derive(Clone, Debug)]
pub struct Login1 {
    connection: Connection,
}

impl Login1 {
    pub async fn connect() -> zbus::Result<Self> {
        Ok(Self {
            connection: Connection::system().await?,
        })
    }

    pub fn from_connection(connection: Connection) -> Self {
        Self { connection }
    }

    /// Installs login1 signal matches before returning. Call this before the
    /// initial enumeration so signals racing with `ListSessions` are queued.
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<Login1Event>, String> {
        let connection = self.connection.clone();
        let (event_tx, event_rx) = mpsc::channel(128);
        let (ready_tx, ready_rx) = oneshot::channel();
        tokio::spawn(async move {
            let manager = match Login1ManagerProxy::new(&connection).await {
                Ok(manager) => manager,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            let mut new_sessions = match manager.receive_session_new().await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            let mut removed_sessions = match manager.receive_session_removed().await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            let dbus = match zbus::fdo::DBusProxy::new(&connection).await {
                Ok(proxy) => proxy,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            let mut owner_changes = match dbus.receive_name_owner_changed().await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }

            loop {
                let event = tokio::select! {
                    message = new_sessions.next() => match message {
                        Some(message) => match message.args() {
                            Ok(args) => Login1Event::SessionNew {
                                id: args.session_id.to_owned(),
                                path: args.object_path.to_owned(),
                            },
                            Err(error) => Login1Event::InvalidSignal(error.to_string()),
                        },
                        None => Login1Event::Disconnected,
                    },
                    message = removed_sessions.next() => match message {
                        Some(message) => match message.args() {
                            Ok(args) => Login1Event::SessionRemoved {
                                id: args.session_id.to_owned(),
                            },
                            Err(error) => Login1Event::InvalidSignal(error.to_string()),
                        },
                        None => Login1Event::Disconnected,
                    },
                    message = owner_changes.next() => match message {
                        Some(message) => match message.args() {
                            Ok(args) if args.name.as_str() == "org.freedesktop.login1" => {
                                Login1Event::ServiceOwnerChanged {
                                    available: args.new_owner.is_some(),
                                }
                            }
                            Ok(_) => continue,
                            Err(error) => Login1Event::InvalidSignal(error.to_string()),
                        },
                        None => Login1Event::Disconnected,
                    },
                };
                let disconnected = event == Login1Event::Disconnected;
                if event_tx.send(event).await.is_err() || disconnected {
                    return;
                }
            }
        });

        match ready_rx.await {
            Ok(Ok(())) => Ok(event_rx),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("login1 subscription task exited during setup".into()),
        }
    }

    pub async fn list_sessions(&self) -> zbus::Result<Vec<SessionInfo>> {
        let manager = Login1ManagerProxy::new(&self.connection).await?;
        let rows = manager.list_sessions().await?;
        let mut sessions = Vec::with_capacity(rows.len());
        for (id, _, _, _, path) in rows {
            match self.session_at(path).await {
                Ok(session) if session.id == id => sessions.push(session),
                Ok(_) => {
                    // The object changed while enumerating. A queued signal or
                    // the second reconciliation will supply its current state.
                }
                Err(error) if is_unknown_object(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(sessions)
    }

    pub async fn session(&self, session_id: &str) -> zbus::Result<SessionInfo> {
        let manager = Login1ManagerProxy::new(&self.connection).await?;
        let path = manager.get_session(session_id).await?;
        self.session_at(path).await
    }

    pub async fn user_runtime_path(&self, uid: u32) -> zbus::Result<String> {
        let manager = Login1ManagerProxy::new(&self.connection).await?;
        let path = manager.get_user(uid).await?;
        let user = Login1UserProxy::builder(&self.connection)
            .path(path)?
            .build()
            .await?;
        user.runtime_path().await
    }

    async fn session_at(&self, path: OwnedObjectPath) -> zbus::Result<SessionInfo> {
        let session = Login1SessionProxy::builder(&self.connection)
            .path(path.clone())?
            .build()
            .await?;
        let (id, (uid, user_path), name, class, service) = tokio::try_join!(
            session.id(),
            session.user(),
            session.name(),
            session.class(),
            session.service(),
        )?;
        let user = Login1UserProxy::builder(&self.connection)
            .path(user_path.clone())?
            .build()
            .await?;
        let runtime_path = user.runtime_path().await?;
        Ok(SessionInfo {
            id,
            uid,
            username: name,
            class,
            service,
            runtime_path,
            object_path: path,
            user_path,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Login1Event {
    SessionNew { id: String, path: OwnedObjectPath },
    SessionRemoved { id: String },
    ServiceOwnerChanged { available: bool },
    InvalidSignal(String),
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    pub id: String,
    pub uid: u32,
    pub username: String,
    pub class: String,
    pub service: String,
    pub runtime_path: String,
    pub object_path: OwnedObjectPath,
    pub user_path: OwnedObjectPath,
}

impl SessionInfo {
    pub fn has_login_class(&self) -> bool {
        matches!(self.class.as_str(), "user" | "user-early")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EligibilityPolicy {
    pub uid_min: u32,
    pub root_eligible: bool,
}

impl EligibilityPolicy {
    pub fn permits(&self, session: &SessionInfo, account: &Account) -> bool {
        session.has_login_class()
            && session.uid == account.uid
            && session.username == account.name
            && !account.is_nobody()
            && ((session.uid == 0 && self.root_eligible)
                || (session.uid != 0 && session.uid >= self.uid_min))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionInventory {
    sessions: HashMap<String, SessionInfo>,
}

impl SessionInventory {
    pub fn reconcile(&mut self, current: Vec<SessionInfo>) -> ReconcileChanges {
        let replacement: HashMap<_, _> = current
            .into_iter()
            .map(|session| (session.id.clone(), session))
            .collect();
        let old_ids: HashSet<_> = self.sessions.keys().cloned().collect();
        let new_ids: HashSet<_> = replacement.keys().cloned().collect();
        let added = new_ids.difference(&old_ids).cloned().collect();
        let removed = old_ids.difference(&new_ids).cloned().collect();
        let changed = old_ids
            .intersection(&new_ids)
            .filter(|id| self.sessions.get(*id) != replacement.get(*id))
            .cloned()
            .collect();
        self.sessions = replacement;
        ReconcileChanges {
            added,
            removed,
            changed,
        }
    }

    pub fn insert(&mut self, session: SessionInfo) -> Option<SessionInfo> {
        self.sessions.insert(session.id.clone(), session)
    }

    pub fn remove(&mut self, session_id: &str) -> Option<SessionInfo> {
        self.sessions.remove(session_id)
    }

    pub fn get(&self, session_id: &str) -> Option<&SessionInfo> {
        self.sessions.get(session_id)
    }

    pub fn values(&self) -> impl Iterator<Item = &SessionInfo> {
        self.sessions.values()
    }

    pub fn sessions_for_uid(&self, uid: u32) -> impl Iterator<Item = &SessionInfo> {
        self.sessions
            .values()
            .filter(move |session| session.uid == uid)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileChanges {
    pub added: HashSet<String>,
    pub removed: HashSet<String>,
    pub changed: HashSet<String>,
}

fn is_unknown_object(error: &zbus::Error) -> bool {
    let rendered = error.to_string();
    rendered.contains("UnknownObject") || rendered.contains("NoSuchSession")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn session(id: &str, uid: u32, class: &str) -> SessionInfo {
        SessionInfo {
            id: id.into(),
            uid,
            username: if uid == 0 { "root" } else { "alice" }.into(),
            class: class.into(),
            service: "login".into(),
            runtime_path: format!("/run/user/{uid}"),
            object_path: OwnedObjectPath::try_from(format!("/session/{id}")).unwrap(),
            user_path: OwnedObjectPath::try_from(format!("/user/{uid}")).unwrap(),
        }
    }

    fn account(uid: u32, name: &str) -> Account {
        Account {
            uid,
            gid: uid,
            name: name.into(),
            home: PathBuf::from(format!("/home/{name}")),
            shell: "/bin/sh".into(),
        }
    }

    #[test]
    fn only_normal_login_classes_are_eligible() {
        let policy = EligibilityPolicy {
            uid_min: 1000,
            root_eligible: false,
        };
        let alice = account(1000, "alice");
        for class in ["user", "user-early"] {
            assert!(policy.permits(&session("c1", 1000, class), &alice));
        }
        for class in [
            "background",
            "background-light",
            "manager",
            "manager-early",
            "greeter",
            "lock-screen",
        ] {
            assert!(!policy.permits(&session("c1", 1000, class), &alice));
        }
    }

    #[test]
    fn excludes_root_system_users_nobody_and_account_mismatches() {
        let policy = EligibilityPolicy {
            uid_min: 1000,
            root_eligible: false,
        };
        assert!(!policy.permits(&session("c1", 0, "user"), &account(0, "root")));
        assert!(!policy.permits(&session("c1", 999, "user"), &account(999, "alice")));
        assert!(!policy.permits(&session("c1", 65_534, "user"), &account(65_534, "nobody")));
        assert!(!policy.permits(&session("c1", 1000, "user"), &account(1001, "alice")));
        assert!(!policy.permits(&session("c1", 1000, "user"), &account(1000, "mallory")));
    }

    #[test]
    fn root_requires_explicit_policy() {
        let policy = EligibilityPolicy {
            uid_min: 1000,
            root_eligible: true,
        };
        assert!(policy.permits(&session("c1", 0, "user"), &account(0, "root")));
    }

    #[test]
    fn inventory_reconciliation_reports_all_differences() {
        let mut inventory = SessionInventory::default();
        let first = inventory.reconcile(vec![session("c1", 1000, "user")]);
        assert_eq!(first.added, HashSet::from(["c1".into()]));

        let second = inventory.reconcile(vec![
            session("c1", 1000, "user-early"),
            session("c2", 1000, "user"),
        ]);
        assert_eq!(second.added, HashSet::from(["c2".into()]));
        assert_eq!(second.changed, HashSet::from(["c1".into()]));

        let third = inventory.reconcile(vec![]);
        assert_eq!(third.removed, HashSet::from(["c1".into(), "c2".into()]));
    }

    #[test]
    fn background_session_never_contributes_to_real_session_count() {
        let policy = EligibilityPolicy {
            uid_min: 1000,
            root_eligible: false,
        };
        let alice = account(1000, "alice");
        let mut inventory = SessionInventory::default();
        inventory.reconcile(vec![
            session("real", 1000, "user"),
            session("lease", 1000, "background"),
        ]);
        let count = inventory
            .sessions_for_uid(1000)
            .filter(|candidate| policy.permits(candidate, &alice))
            .count();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[ignore = "requires a running login1 system service"]
    async fn enumerates_live_login1() {
        let login1 = Login1::connect().await.unwrap();
        let mut events = login1.subscribe().await.unwrap();
        let sessions = login1.list_sessions().await.unwrap();
        for session in sessions {
            assert!(!session.id.is_empty());
            assert!(session.runtime_path.starts_with('/'));
            assert_eq!(login1.session(&session.id).await.unwrap().uid, session.uid);
        }
        events.close();
    }
}
