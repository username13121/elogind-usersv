use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use elogind_usersv_core::{
    account::{login_defs_uid_min, resolve_uid},
    config::{
        Config, DEFAULT_CONFIG_PATH, DEFAULT_CONTROL_SOCKET, DEFAULT_RUNTIME_DIRECTORY,
        DEFAULT_SUPERVISOR_PATH, INTERNAL_PAM_SERVICE, LogLevel,
    },
    ipc::{MessageIoError, PeerCredentials, SeqPacket, SeqPacketListener},
    security::{verify_root_owned_file, verify_runtime_directory},
};
use elogind_usersv_protocol::{
    DaemonToHelper, ErrorCode, HelperToDaemon, PamReply, PamRequest, WireMessage,
};
use log::{debug, error, info, warn};
use tokio::{
    io::unix::AsyncFd,
    sync::{Semaphore, mpsc, oneshot},
    time::{Instant, MissedTickBehavior},
};

use crate::{
    login1::{EligibilityPolicy, Login1, Login1Event, SessionInfo, SessionInventory},
    state::{Action, UserMachine, UserManagerState},
};

const MAX_PENDING_REQUESTS: usize = 1024;
const MAX_PENDING_REQUESTS_PER_UID: usize = 64;

pub async fn run() -> Result<()> {
    let arguments = Arguments::parse()?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("elogind-usersvd must run as root");
    }
    if arguments.config_path.exists() {
        verify_root_owned_file(&arguments.config_path, false)
            .context("configuration file is not trusted")?;
    }
    verify_root_owned_file(&arguments.supervisor_path, true)
        .context("supervisor executable is not trusted")?;
    let config = Config::load_or_default(&arguments.config_path)?;
    initialize_logging(config.logging_verbosity);
    prepare_runtime_directory()?;
    let _daemon_lock = DaemonLock::acquire()?;
    prepare_socket_path()?;

    let listener = SeqPacketListener::bind(DEFAULT_CONTROL_SOCKET, 0o666, 128)
        .context("bind PAM control socket")?;
    listener.set_nonblocking(true)?;
    let listener = Arc::new(AsyncFd::new(listener)?);

    let (event_tx, event_rx) = mpsc::channel(512);
    tokio::spawn(accept_clients(
        listener,
        event_tx.clone(),
        config.login_readiness_timeout() + Duration::from_secs(2),
    ));

    let (login1, login_events, login1_available) = connect_login1().await;
    let mut daemon = Daemon {
        config,
        config_path: arguments.config_path,
        supervisor_path: arguments.supervisor_path,
        policy: EligibilityPolicy {
            uid_min: login_defs_uid_min("/etc/login.defs"),
            root_eligible: false,
        },
        login1,
        login_events,
        login1_available,
        inventory: SessionInventory::default(),
        eligible: HashMap::new(),
        machines: HashMap::new(),
        helpers: HashMap::new(),
        pending: HashMap::new(),
        next_request: 1,
        next_generation: 1,
        event_tx,
        event_rx,
    };
    daemon.policy.root_eligible = daemon.config.root_eligible;
    if daemon.login1_available {
        daemon.reconcile().await;
        // A second snapshot closes races between match installation and the
        // first ListSessions result even if signal delivery is delayed.
        daemon.reconcile().await;
    }
    daemon.run_loop().await
}

struct Daemon {
    config: Config,
    config_path: PathBuf,
    supervisor_path: PathBuf,
    policy: EligibilityPolicy,
    login1: Option<Login1>,
    login_events: mpsc::Receiver<Login1Event>,
    login1_available: bool,
    inventory: SessionInventory,
    eligible: HashMap<u32, HashSet<String>>,
    machines: HashMap<u32, UserMachine>,
    helpers: HashMap<u32, HelperHandle>,
    pending: HashMap<u64, PendingRequest>,
    next_request: u64,
    next_generation: u64,
    event_tx: mpsc::Sender<DaemonEvent>,
    event_rx: mpsc::Receiver<DaemonEvent>,
}

struct PendingRequest {
    uid: u32,
    sender: oneshot::Sender<PamReply>,
}

struct HelperHandle {
    generation: u64,
    control: Arc<AsyncFd<SeqPacket>>,
    internal_session_id: Option<String>,
    manager_pid: Option<u32>,
}

#[derive(Debug)]
enum DaemonEvent {
    Pam {
        request: PamRequest,
        credentials: PeerCredentials,
        reply: oneshot::Sender<PamReply>,
    },
    PamExpired {
        request: u64,
    },
    HelperMessage {
        uid: u32,
        generation: u64,
        message: HelperToDaemon,
    },
    HelperSocketClosed {
        uid: u32,
        generation: u64,
        error: Option<String>,
    },
    HelperExited {
        uid: u32,
        generation: u64,
        status: String,
    },
    BackoffElapsed {
        uid: u32,
        generation: u64,
        attempt: u32,
    },
    SpawnReplacement {
        uid: u32,
    },
}

impl Daemon {
    async fn run_loop(&mut self) -> Result<()> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut reconcile_interval = tokio::time::interval(Duration::from_secs(30));
        reconcile_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
        reconnect_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                signal = terminate.recv() => {
                    if signal.is_some() {
                        info!("event=daemon_shutdown reason=SIGTERM");
                        break;
                    }
                }
                signal = interrupt.recv() => {
                    if signal.is_some() {
                        info!("event=daemon_shutdown reason=SIGINT");
                        break;
                    }
                }
                event = self.event_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_daemon_event(event).await;
                    }
                }
                event = self.login_events.recv(), if self.login1.is_some() => {
                    if let Some(event) = event {
                        self.handle_login1_event(event).await;
                    } else {
                        self.mark_login1_disconnected();
                    }
                }
                _ = reconnect_interval.tick(), if !self.login1_available => {
                    self.try_recover_login1().await;
                }
                _ = reconcile_interval.tick(), if self.login1_available => {
                    self.reconcile().await;
                }
            }
        }
        self.orderly_shutdown().await;
        Ok(())
    }

    async fn handle_daemon_event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::Pam {
                request,
                credentials,
                reply,
            } => self.handle_pam_request(request, credentials, reply).await,
            DaemonEvent::PamExpired { request } => {
                if let Some(pending) = self.pending.remove(&request) {
                    if let Some(machine) = self.machines.get_mut(&pending.uid) {
                        machine.cancel_pam_request(request);
                    }
                    let _ = pending.sender.send(error_reply(ErrorCode::TimedOut));
                }
            }
            DaemonEvent::HelperMessage {
                uid,
                generation,
                message,
            } => self.handle_helper_message(uid, generation, message).await,
            DaemonEvent::HelperSocketClosed {
                uid,
                generation,
                error,
            } => {
                if self.helper_matches(uid, generation) {
                    match error {
                        Some(error) => warn!(
                            "event=helper_control_closed uid={uid} generation={generation} error={error:?}"
                        ),
                        None => {
                            debug!("event=helper_control_closed uid={uid} generation={generation}")
                        }
                    }
                }
            }
            DaemonEvent::HelperExited {
                uid,
                generation,
                status,
            } => self.helper_exited(uid, generation, &status).await,
            DaemonEvent::BackoffElapsed {
                uid,
                generation,
                attempt,
            } => {
                let actions = self
                    .machines
                    .get_mut(&uid)
                    .map(|machine| machine.backoff_elapsed(generation, attempt))
                    .unwrap_or_default();
                self.apply_actions(uid, actions).await;
            }
            DaemonEvent::SpawnReplacement { uid } => {
                if self.machines.get(&uid).is_some_and(|machine| {
                    machine.eligible_sessions > 0 && machine.state == UserManagerState::Absent
                }) {
                    self.spawn_helper(uid).await;
                }
            }
        }
    }

    async fn handle_login1_event(&mut self, event: Login1Event) {
        match event {
            Login1Event::SessionNew { id, .. } => self.refresh_session(&id).await,
            Login1Event::SessionRemoved { id } => self.remove_session(&id).await,
            Login1Event::ServiceOwnerChanged { available: false } => {
                self.login1_available = false;
                warn!("event=login1_unavailable action=retain_existing_managers");
            }
            Login1Event::ServiceOwnerChanged { available: true } => {
                self.login1_available = true;
                info!("event=login1_reconnected action=full_reconciliation");
                self.reconcile().await;
                self.verify_active_leases().await;
            }
            Login1Event::InvalidSignal(error) => {
                warn!("event=invalid_login1_signal error={error:?}")
            }
            Login1Event::Disconnected => self.mark_login1_disconnected(),
        }
    }

    fn mark_login1_disconnected(&mut self) {
        self.login1_available = false;
        self.login1 = None;
        let (_sender, receiver) = mpsc::channel(1);
        self.login_events = receiver;
        warn!("event=system_bus_disconnected action=schedule_reconnect");
    }

    async fn try_recover_login1(&mut self) {
        if self.login1.is_some() {
            self.reconcile().await;
            if self.login1_available {
                info!("event=login1_service_recovered action=verify_leases");
                self.verify_active_leases().await;
            }
            return;
        }
        let (login1, events, available) = connect_login1().await;
        if let Some(login1) = login1 {
            self.login1 = Some(login1);
            self.login_events = events;
            self.login1_available = available;
            if available {
                info!("event=system_bus_reconnected action=full_reconciliation");
                self.reconcile().await;
                self.verify_active_leases().await;
            }
        }
    }

    async fn reconcile(&mut self) {
        let Some(login1) = self.login1.clone() else {
            return;
        };
        match login1.list_sessions().await {
            Ok(sessions) => {
                self.login1_available = true;
                let new_eligible = self.filter_eligible(&sessions);
                let changes = self.inventory.reconcile(sessions);
                debug!(
                    "event=session_reconciliation added={} removed={} changed={}",
                    changes.added.len(),
                    changes.removed.len(),
                    changes.changed.len()
                );
                self.replace_eligible(new_eligible).await;
            }
            Err(error) => {
                self.login1_available = false;
                warn!("event=session_reconciliation_failed error={error:?}");
            }
        }
    }

    fn filter_eligible(&self, sessions: &[SessionInfo]) -> HashMap<u32, HashSet<String>> {
        let mut eligible: HashMap<u32, HashSet<String>> = HashMap::new();
        for session in sessions {
            let Ok(account) = resolve_uid(session.uid) else {
                warn!(
                    "event=session_excluded session_id={:?} uid={} reason=nss_resolution",
                    session.id, session.uid
                );
                continue;
            };
            if self.policy.permits(session, &account) {
                eligible
                    .entry(session.uid)
                    .or_default()
                    .insert(session.id.clone());
            }
        }
        eligible
    }

    async fn replace_eligible(&mut self, replacement: HashMap<u32, HashSet<String>>) {
        let uids: HashSet<_> = self
            .eligible
            .keys()
            .chain(replacement.keys())
            .copied()
            .collect();
        self.eligible = replacement;
        for uid in uids {
            let count = self.eligible.get(&uid).map_or(0, HashSet::len);
            let machine = self
                .machines
                .entry(uid)
                .or_insert_with(|| UserMachine::new(uid));
            let old = machine.eligible_sessions;
            let actions = machine.set_eligible_sessions(count);
            if old != count {
                info!("event=eligible_session_count uid={uid} old={old} new={count}");
            }
            self.apply_actions(uid, actions).await;
        }
    }

    async fn refresh_session(&mut self, session_id: &str) {
        let Some(login1) = self.login1.clone() else {
            return;
        };
        match login1.session(session_id).await {
            Ok(session) => {
                let eligible = resolve_uid(session.uid)
                    .ok()
                    .is_some_and(|account| self.policy.permits(&session, &account));
                let uid = session.uid;
                self.inventory.insert(session.clone());
                if eligible {
                    let inserted = self
                        .eligible
                        .entry(uid)
                        .or_default()
                        .insert(session.id.clone());
                    if inserted {
                        self.update_eligible_count(uid).await;
                    }
                }
            }
            Err(error) => {
                debug!("event=session_new_vanished session_id={session_id:?} error={error:?}")
            }
        }
    }

    async fn remove_session(&mut self, session_id: &str) {
        let removed = self.inventory.remove(session_id);
        let uid = removed.as_ref().map(|session| session.uid).or_else(|| {
            self.eligible
                .iter()
                .find_map(|(uid, sessions)| sessions.contains(session_id).then_some(*uid))
        });
        let Some(uid) = uid else {
            return;
        };
        if self
            .eligible
            .get_mut(&uid)
            .is_some_and(|sessions| sessions.remove(session_id))
        {
            self.update_eligible_count(uid).await;
        }
    }

    async fn update_eligible_count(&mut self, uid: u32) {
        let count = self.eligible.get(&uid).map_or(0, HashSet::len);
        let machine = self
            .machines
            .entry(uid)
            .or_insert_with(|| UserMachine::new(uid));
        let old = machine.eligible_sessions;
        let actions = machine.set_eligible_sessions(count);
        info!("event=eligible_session_count uid={uid} old={old} new={count}");
        self.apply_actions(uid, actions).await;
    }

    async fn handle_pam_request(
        &mut self,
        request: PamRequest,
        credentials: PeerCredentials,
        reply: oneshot::Sender<PamReply>,
    ) {
        if !self.login1_available {
            let _ = reply.send(error_reply(ErrorCode::Login1Unavailable));
            return;
        }
        let PamRequest::EnsureManagerReady {
            session_id,
            runtime_dir,
        } = request;
        let Some(login1) = self.login1.clone() else {
            let _ = reply.send(error_reply(ErrorCode::Login1Unavailable));
            return;
        };
        let session = match login1.session(&session_id).await {
            Ok(session) => session,
            Err(error) => {
                warn!(
                    "event=pam_request_rejected peer_uid={} session_id={session_id:?} reason=session_lookup error={error:?}",
                    credentials.uid
                );
                let _ = reply.send(error_reply(ErrorCode::SessionNotFound));
                return;
            }
        };
        if session.runtime_path != runtime_dir {
            warn!(
                "event=pam_request_rejected peer_uid={} session_id={session_id:?} uid={} reason=runtime_mismatch",
                credentials.uid, session.uid
            );
            let _ = reply.send(error_reply(ErrorCode::InvalidRequest));
            return;
        }
        let account = match resolve_uid(session.uid) {
            Ok(account) => account,
            Err(error) => {
                warn!(
                    "event=pam_request_rejected session_id={session_id:?} uid={} reason=nss error={error:?}",
                    session.uid
                );
                let _ = reply.send(error_reply(ErrorCode::SessionIneligible));
                return;
            }
        };
        if !self.policy.permits(&session, &account) {
            let _ = reply.send(error_reply(ErrorCode::SessionIneligible));
            return;
        }
        if credentials.uid != 0 && credentials.uid != session.uid {
            warn!(
                "event=pam_request_rejected peer_uid={} session_id={session_id:?} uid={} reason=peer_credentials",
                credentials.uid, session.uid
            );
            let _ = reply.send(error_reply(ErrorCode::PermissionDenied));
            return;
        }

        let pending_for_uid = self
            .pending
            .values()
            .filter(|pending| pending.uid == session.uid)
            .count();
        if self.pending.len() >= MAX_PENDING_REQUESTS
            || pending_for_uid >= MAX_PENDING_REQUESTS_PER_UID
        {
            let _ = reply.send(error_reply(ErrorCode::Internal));
            return;
        }

        self.inventory.insert(session.clone());
        if self
            .eligible
            .entry(session.uid)
            .or_default()
            .insert(session.id.clone())
        {
            self.update_eligible_count(session.uid).await;
        }

        let request_id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        self.pending.insert(
            request_id,
            PendingRequest {
                uid: session.uid,
                sender: reply,
            },
        );
        let expiration_sender = self.event_tx.clone();
        let expiration = self.config.login_readiness_timeout();
        tokio::spawn(async move {
            tokio::time::sleep(expiration).await;
            let _ = expiration_sender
                .send(DaemonEvent::PamExpired {
                    request: request_id,
                })
                .await;
        });
        let actions = self
            .machines
            .entry(session.uid)
            .or_insert_with(|| UserMachine::new(session.uid))
            .add_pam_request(request_id);
        self.apply_actions(session.uid, actions).await;
    }

    async fn handle_helper_message(&mut self, uid: u32, generation: u64, message: HelperToDaemon) {
        if !self.helper_matches(uid, generation) {
            debug!("event=stale_helper_message uid={uid} generation={generation}");
            return;
        }
        match message {
            HelperToDaemon::LeaseOpened {
                session_id,
                runtime_dir,
            } => match self.verify_lease(uid, &session_id, &runtime_dir).await {
                Ok(()) => {
                    if let Some(helper) = self.helpers.get_mut(&uid) {
                        helper.internal_session_id = Some(session_id.clone());
                    }
                    info!(
                        "event=lease_verified uid={uid} generation={generation} manager_session_id={session_id:?}"
                    );
                    if self
                        .send_helper(uid, generation, &DaemonToHelper::LeaseAccepted)
                        .await
                        .is_ok()
                    {
                        let actions = self
                            .machines
                            .get(&uid)
                            .map(UserMachine::lease_accepted)
                            .unwrap_or_default();
                        self.apply_actions(uid, actions).await;
                    }
                }
                Err(error) => {
                    error!(
                        "event=lease_rejected uid={uid} generation={generation} error={error:#}"
                    );
                    let _ = self
                        .send_helper(
                            uid,
                            generation,
                            &DaemonToHelper::LeaseRejected {
                                reason: "internal elogind lease verification failed".into(),
                            },
                        )
                        .await;
                    if let Some(machine) = self.machines.get_mut(&uid) {
                        machine.state = UserManagerState::Stopping {
                            generation,
                            restart_after_stop: machine.eligible_sessions > 0,
                        };
                    }
                }
            },
            HelperToDaemon::ManagerSpawned { pid } => {
                if let Some(helper) = self.helpers.get_mut(&uid) {
                    helper.manager_pid = Some(pid);
                }
                if let Some(machine) = self.machines.get_mut(&uid) {
                    machine.manager_spawned(generation, pid);
                }
                info!("event=manager_spawned uid={uid} generation={generation} manager_pid={pid}");
            }
            HelperToDaemon::ReadinessPayload { payload } => debug!(
                "event=readiness_payload uid={uid} generation={generation} payload={payload:?}"
            ),
            HelperToDaemon::ReadySucceeded => {
                let actions = self
                    .machines
                    .get_mut(&uid)
                    .map(|machine| machine.ready_succeeded(generation))
                    .unwrap_or_default();
                info!("event=state_transition uid={uid} generation={generation} state=ready");
                self.apply_actions(uid, actions).await;
            }
            HelperToDaemon::StartFailed { message } => {
                warn!(
                    "event=manager_start_failed uid={uid} generation={generation} error={message:?}"
                );
                let actions = self
                    .machines
                    .get_mut(&uid)
                    .map(|machine| machine.startup_failed(generation))
                    .unwrap_or_default();
                self.apply_actions(uid, actions).await;
            }
            HelperToDaemon::ManagerExited { status } => {
                if let Some(helper) = self.helpers.get_mut(&uid) {
                    helper.manager_pid = None;
                }
                warn!("event=manager_exited uid={uid} generation={generation} status={status}");
                let actions = self
                    .machines
                    .get_mut(&uid)
                    .map(|machine| machine.manager_exited(generation))
                    .unwrap_or_default();
                self.apply_actions(uid, actions).await;
            }
            HelperToDaemon::ShutdownComplete => {
                debug!("event=helper_shutdown_complete uid={uid} generation={generation}")
            }
            HelperToDaemon::Fatal { message } => {
                error!("event=helper_fatal uid={uid} generation={generation} error={message:?}")
            }
        }
    }

    async fn verify_lease(&self, uid: u32, session_id: &str, runtime_dir: &str) -> Result<()> {
        let login1 = self.login1.as_ref().context("login1 is unavailable")?;
        if session_id.is_empty() || !Path::new(runtime_dir).is_absolute() {
            bail!("invalid PAM lease environment");
        }
        let session = login1.session(session_id).await?;
        if session.uid != uid {
            bail!("internal session UID {} does not match {uid}", session.uid);
        }
        if session.class != "background" {
            bail!(
                "internal session class is {:?}, not background",
                session.class
            );
        }
        if session.service != INTERNAL_PAM_SERVICE {
            bail!(
                "internal session service is {:?}, expected {INTERNAL_PAM_SERVICE}",
                session.service
            );
        }
        if session.runtime_path != runtime_dir {
            bail!(
                "PAM runtime path {:?} does not match login1 RuntimePath {:?}",
                runtime_dir,
                session.runtime_path
            );
        }
        verify_runtime_directory(Path::new(runtime_dir), uid)?;
        Ok(())
    }

    async fn verify_active_leases(&mut self) {
        let leases: Vec<_> = self
            .helpers
            .iter()
            .filter_map(|(uid, helper)| {
                helper
                    .internal_session_id
                    .as_ref()
                    .map(|session| (*uid, helper.generation, session.clone()))
            })
            .collect();
        for (uid, generation, session_id) in leases {
            let runtime_dir = self
                .inventory
                .sessions_for_uid(uid)
                .next()
                .map(|session| session.runtime_path.clone());
            let verified = match runtime_dir {
                Some(runtime_dir) => self.verify_lease(uid, &session_id, &runtime_dir).await,
                None => Err(anyhow::anyhow!("user has no login1 user RuntimePath")),
            };
            if let Err(error) = verified {
                error!(
                    "event=lease_lost_after_reconnect uid={uid} generation={generation} error={error:#}"
                );
                if let Some(machine) = self.machines.get_mut(&uid) {
                    machine.state = UserManagerState::Stopping {
                        generation,
                        restart_after_stop: machine.eligible_sessions > 0,
                    };
                }
                let _ = self
                    .send_helper(uid, generation, &DaemonToHelper::Shutdown)
                    .await;
            }
        }
    }

    async fn apply_actions(&mut self, uid: u32, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::SpawnHelper => self.spawn_helper(uid).await,
                Action::StartManager {
                    generation,
                    attempt,
                } => {
                    info!(
                        "event=state_transition uid={uid} generation={generation} state=starting attempt={attempt}"
                    );
                    if let Err(error) = self
                        .send_helper(uid, generation, &DaemonToHelper::StartManager { attempt })
                        .await
                    {
                        warn!(
                            "event=helper_command_failed uid={uid} generation={generation} error={error:#}"
                        );
                    }
                }
                Action::ShutdownHelper { generation } => {
                    info!(
                        "event=state_transition uid={uid} generation={generation} state=stopping"
                    );
                    let _ = self
                        .send_helper(uid, generation, &DaemonToHelper::Shutdown)
                        .await;
                }
                Action::ScheduleBackoff {
                    generation,
                    attempt,
                } => {
                    let delay = self.config.restart_delay(attempt.saturating_sub(1));
                    info!(
                        "event=restart_scheduled uid={uid} generation={generation} attempt={attempt} delay_ms={}",
                        delay.as_millis()
                    );
                    let sender = self.event_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = sender
                            .send(DaemonEvent::BackoffElapsed {
                                uid,
                                generation,
                                attempt,
                            })
                            .await;
                    });
                }
                Action::ReplyReady(requests) => {
                    for request in requests {
                        self.reply(request, PamReply::Ready);
                    }
                }
                Action::ReplyError { requests, code } => {
                    for request in requests {
                        self.reply(request, error_reply(code));
                    }
                }
            }
        }
    }

    fn reply(&mut self, request: u64, reply: PamReply) {
        if let Some(pending) = self.pending.remove(&request) {
            let _ = pending.sender.send(reply);
        }
    }

    async fn spawn_helper(&mut self, uid: u32) {
        if self.helpers.contains_key(&uid) {
            return;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        match spawn_helper_process(
            uid,
            generation,
            &self.supervisor_path,
            &self.config_path,
            self.event_tx.clone(),
        ) {
            Ok(handle) => {
                self.helpers.insert(uid, handle);
                self.machines
                    .entry(uid)
                    .or_insert_with(|| UserMachine::new(uid))
                    .helper_spawned(generation);
                info!(
                    "event=state_transition uid={uid} generation={generation} state=starting backend={:?}",
                    self.config.backend
                );
            }
            Err(error) => {
                error!("event=helper_spawn_failed uid={uid} error={error:#}");
                let sender = self.event_tx.clone();
                let delay = self.config.restart_backoff_minimum();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sender.send(DaemonEvent::SpawnReplacement { uid }).await;
                });
            }
        }
    }

    async fn send_helper(&self, uid: u32, generation: u64, message: &DaemonToHelper) -> Result<()> {
        let helper = self.helpers.get(&uid).context("helper is absent")?;
        if helper.generation != generation {
            bail!("helper generation mismatch");
        }
        async_send(&helper.control, message).await
    }

    fn helper_matches(&self, uid: u32, generation: u64) -> bool {
        self.helpers
            .get(&uid)
            .is_some_and(|helper| helper.generation == generation)
    }

    async fn helper_exited(&mut self, uid: u32, generation: u64, status: &str) {
        if !self.helper_matches(uid, generation) {
            return;
        }
        self.helpers.remove(&uid);
        warn!("event=helper_exited uid={uid} generation={generation} status={status:?}");
        let actions = self
            .machines
            .get_mut(&uid)
            .map(|machine| machine.helper_exited(generation))
            .unwrap_or_default();
        let mut delayed_spawn = false;
        let mut remaining = Vec::new();
        for action in actions {
            if action == Action::SpawnHelper {
                delayed_spawn = true;
            } else {
                remaining.push(action);
            }
        }
        self.apply_actions(uid, remaining).await;
        if delayed_spawn {
            let sender = self.event_tx.clone();
            let delay = self.config.restart_backoff_minimum();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = sender.send(DaemonEvent::SpawnReplacement { uid }).await;
            });
        }
    }

    async fn orderly_shutdown(&mut self) {
        let uids: Vec<_> = self.machines.keys().copied().collect();
        for uid in uids {
            let actions = self
                .machines
                .get_mut(&uid)
                .map(UserMachine::begin_shutdown)
                .unwrap_or_default();
            self.apply_actions(uid, actions).await;
        }
        let total = self.config.graceful_stop_timeout() * 2
            + self.config.forced_stop_timeout()
            + Duration::from_secs(5);
        let deadline = Instant::now() + total;
        while !self.helpers.is_empty() && Instant::now() < deadline {
            let remaining = deadline - Instant::now();
            match tokio::time::timeout(remaining, self.event_rx.recv()).await {
                Ok(Some(DaemonEvent::HelperExited {
                    uid,
                    generation,
                    status,
                })) => self.helper_exited(uid, generation, &status).await,
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        if !self.helpers.is_empty() {
            warn!(
                "event=daemon_shutdown_timeout remaining_helpers={}",
                self.helpers.len()
            );
            // Dropping control sockets causes each helper to execute its
            // independent safe-shutdown path.
            self.helpers.clear();
        }
        for (_, pending) in self.pending.drain() {
            let _ = pending.sender.send(error_reply(ErrorCode::Internal));
        }
    }
}

async fn connect_login1() -> (Option<Login1>, mpsc::Receiver<Login1Event>, bool) {
    match Login1::connect().await {
        Ok(login1) => match login1.subscribe().await {
            Ok(events) => (Some(login1), events, true),
            Err(error) => {
                warn!("event=login1_subscription_failed error={error:?}");
                let (_sender, receiver) = mpsc::channel(1);
                (None, receiver, false)
            }
        },
        Err(error) => {
            warn!("event=login1_connection_failed error={error:?}");
            let (_sender, receiver) = mpsc::channel(1);
            (None, receiver, false)
        }
    }
}

fn spawn_helper_process(
    uid: u32,
    generation: u64,
    supervisor_path: &Path,
    config_path: &Path,
    event_tx: mpsc::Sender<DaemonEvent>,
) -> Result<HelperHandle> {
    if !supervisor_path.is_absolute() {
        bail!("supervisor path is not absolute");
    }
    let (daemon_socket, helper_socket) = SeqPacket::pair()?;
    daemon_socket.set_nonblocking(true)?;
    let helper_fd = helper_socket.as_raw_fd();
    let mut command = Command::new(supervisor_path);
    command
        .arg("--control-fd")
        .arg(helper_fd.to_string())
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null());
    // SAFETY: pre_exec runs after fork in the child. fcntl is async-signal-safe,
    // and the closure performs no allocation.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(helper_fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn().context("spawn per-user supervisor")?;
    drop(helper_socket);
    let control = Arc::new(AsyncFd::new(daemon_socket)?);

    let reader_control = control.clone();
    let reader_tx = event_tx.clone();
    tokio::spawn(async move {
        loop {
            match async_recv::<HelperToDaemon>(&reader_control).await {
                Ok(message) => {
                    if reader_tx
                        .send(DaemonEvent::HelperMessage {
                            uid,
                            generation,
                            message,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let eof = error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof);
                    let _ = reader_tx
                        .send(DaemonEvent::HelperSocketClosed {
                            uid,
                            generation,
                            error: (!eof).then(|| format!("{error:#}")),
                        })
                        .await;
                    return;
                }
            }
        }
    });
    tokio::task::spawn_blocking(move || {
        let status = child
            .wait()
            .map(|status| status.to_string())
            .unwrap_or_else(|error| format!("wait failed: {error}"));
        let _ = event_tx.blocking_send(DaemonEvent::HelperExited {
            uid,
            generation,
            status,
        });
    });

    Ok(HelperHandle {
        generation,
        control,
        internal_session_id: None,
        manager_pid: None,
    })
}

async fn accept_clients(
    listener: Arc<AsyncFd<SeqPacketListener>>,
    events: mpsc::Sender<DaemonEvent>,
    wait_timeout: Duration,
) {
    let permits = Arc::new(Semaphore::new(128));
    loop {
        let permit = match permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        let mut readiness = match listener.readable().await {
            Ok(readiness) => readiness,
            Err(error) => {
                error!("event=pam_listener_failed error={error:?}");
                return;
            }
        };
        match readiness.try_io(|listener| listener.get_ref().accept()) {
            Ok(Ok(socket)) => {
                let events = events.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_pam_client(socket, events, wait_timeout).await {
                        debug!("event=pam_client_failed error={error:#}");
                    }
                });
            }
            Ok(Err(error)) => warn!("event=pam_accept_failed error={error:?}"),
            Err(_) => continue,
        }
    }
}

async fn handle_pam_client(
    socket: SeqPacket,
    events: mpsc::Sender<DaemonEvent>,
    wait_timeout: Duration,
) -> Result<()> {
    let credentials = socket.peer_credentials()?;
    socket.set_nonblocking(true)?;
    let socket = AsyncFd::new(socket)?;
    let request = tokio::time::timeout(Duration::from_secs(5), async_recv::<PamRequest>(&socket))
        .await
        .context("PAM request read timed out")??;
    let (reply_tx, reply_rx) = oneshot::channel();
    events
        .send(DaemonEvent::Pam {
            request,
            credentials,
            reply: reply_tx,
        })
        .await
        .context("daemon event loop closed")?;
    let reply = match tokio::time::timeout(wait_timeout, reply_rx).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) => error_reply(ErrorCode::Internal),
        Err(_) => error_reply(ErrorCode::TimedOut),
    };
    tokio::time::timeout(Duration::from_secs(5), async_send(&socket, &reply))
        .await
        .context("PAM reply write timed out")??;
    Ok(())
}

async fn async_recv<M: WireMessage>(socket: &AsyncFd<SeqPacket>) -> Result<M> {
    loop {
        let mut readiness = socket.readable().await?;
        match readiness
            .try_io(|socket| socket.get_ref().recv::<M>().map_err(message_io_to_io_error))
        {
            Ok(result) => return Ok(result?),
            Err(_) => continue,
        }
    }
}

async fn async_send<M: WireMessage>(socket: &AsyncFd<SeqPacket>, message: &M) -> Result<()> {
    let packet = message.encode()?;
    loop {
        let mut readiness = socket.writable().await?;
        match readiness.try_io(|socket| socket.get_ref().send_packet(&packet)) {
            Ok(result) => return Ok(result?),
            Err(_) => continue,
        }
    }
}

fn message_io_to_io_error(error: MessageIoError) -> io::Error {
    match error {
        MessageIoError::Io(error) => error,
        MessageIoError::Protocol(error) => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn error_reply(code: ErrorCode) -> PamReply {
    PamReply::Error {
        code,
        message: "user service manager is unavailable".into(),
    }
}

struct DaemonLock {
    _file: File,
}

impl DaemonLock {
    fn acquire() -> Result<Self> {
        let path = Path::new(DEFAULT_RUNTIME_DIRECTORY).join("daemon.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .context("open daemon lock")?;
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!("unsafe daemon lock metadata");
        }
        // SAFETY: file is a valid descriptor and flock has no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                bail!("another elogind-usersvd instance is already running");
            }
            return Err(error).context("acquire daemon lock");
        }
        Ok(Self { _file: file })
    }
}

fn prepare_runtime_directory() -> Result<()> {
    let path = Path::new(DEFAULT_RUNTIME_DIRECTORY);
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create daemon runtime directory"),
    }
    let metadata = fs::symlink_metadata(path)?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        bail!("unsafe daemon runtime directory metadata");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn prepare_socket_path() -> Result<()> {
    let path = Path::new(DEFAULT_CONTROL_SOCKET);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            if !metadata.file_type().is_socket()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
            {
                bail!("refusing to replace unsafe control socket path");
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect control socket path"),
    }
    Ok(())
}

fn initialize_logging(level: LogLevel) {
    let filter = match level {
        LogLevel::Error => log::LevelFilter::Error,
        LogLevel::Warn => log::LevelFilter::Warn,
        LogLevel::Info => log::LevelFilter::Info,
        LogLevel::Debug => log::LevelFilter::Debug,
        LogLevel::Trace => log::LevelFilter::Trace,
    };
    let mut builder = env_logger::Builder::new();
    builder.filter_level(filter).format_timestamp_millis();
    let _ = builder.try_init();
}

struct Arguments {
    config_path: PathBuf,
    supervisor_path: PathBuf,
}

impl Arguments {
    fn parse() -> Result<Self> {
        let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
        let mut supervisor_path = PathBuf::from(DEFAULT_SUPERVISOR_PATH);
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--config") => {
                    config_path = arguments.next().context("--config requires a path")?.into();
                }
                Some("--supervisor") => {
                    supervisor_path = arguments
                        .next()
                        .context("--supervisor requires a path")?
                        .into();
                }
                _ => bail!("unknown daemon argument: {argument:?}"),
            }
        }
        if !config_path.is_absolute() || !supervisor_path.is_absolute() {
            bail!("configuration and supervisor paths must be absolute");
        }
        Ok(Self {
            config_path,
            supervisor_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elogind_usersv_protocol::PROTOCOL_VERSION;

    #[test]
    fn generic_errors_do_not_expose_details() {
        let PamReply::Error { message, .. } = error_reply(ErrorCode::Internal) else {
            panic!("expected error reply");
        };
        assert_eq!(message, "user service manager is unavailable");
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
