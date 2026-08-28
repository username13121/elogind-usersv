mod pam;
mod process;
mod runtime;

use std::{
    io::{self, Read},
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use elogind_usersv_core::{
    account::{Account, resolve_uid},
    config::{Config, DEFAULT_CONFIG_PATH},
    ipc::SeqPacket,
    security::verify_root_owned_file,
};
use elogind_usersv_protocol::{DaemonToHelper, HelperToDaemon, ProcessStatus, ReadinessFrame};
use pam::PamLease;
use process::{Backend, BackendEnvironment, Child};
use runtime::{InstanceState, SignalFd, UserLock};

fn main() {
    if let Err(error) = run() {
        eprintln!("elogind-usersv-supervisor: fatal: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse()?;
    // SAFETY: the daemon passes unique ownership of a connected seqpacket fd.
    let control = unsafe { SeqPacket::from_raw_fd(arguments.control_fd) };
    let credentials = control
        .peer_credentials()
        .context("read daemon peer credentials")?;
    if credentials.uid != 0 {
        bail!("daemon control peer is not root");
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("supervisor must run as root");
    }

    if arguments.config_path.exists() {
        verify_root_owned_file(&arguments.config_path, false)
            .context("configuration file is not trusted")?;
    }
    let config = Config::load_or_default(&arguments.config_path)?;
    runtime::prepare_runtime()?;
    let signals = SignalFd::install()?;
    let account = resolve_uid(arguments.uid)?;
    let _user_lock = UserLock::acquire(account.uid)?;
    let backend = Backend::load(config.backend.clone(), config.backend_config_dir.clone())?;

    let lease = match PamLease::open(&account) {
        Ok(lease) => lease,
        Err(error) => {
            let _ = control.send(&HelperToDaemon::Fatal {
                message: bounded_message(&format!("cannot open internal PAM session: {error:#}")),
            });
            return Err(error);
        }
    };
    let session_id = lease.required("XDG_SESSION_ID")?.to_owned();
    let runtime_dir = lease.required("XDG_RUNTIME_DIR")?.to_owned();
    if session_id.is_empty() || !Path::new(&runtime_dir).is_absolute() {
        bail!("internal PAM session returned invalid lease identifiers");
    }
    if lease.required("XDG_SESSION_CLASS")? != "background"
        || lease.required("XDG_SESSION_TYPE")? != "unspecified"
    {
        bail!("internal PAM session changed the required class or type");
    }
    control.send(&HelperToDaemon::LeaseOpened {
        session_id: session_id.clone(),
        runtime_dir: runtime_dir.clone(),
    })?;

    match wait_for_command(&control, &signals)? {
        ControlEvent::Command(DaemonToHelper::LeaseAccepted) => {}
        ControlEvent::Command(DaemonToHelper::LeaseRejected { reason }) => {
            bail!("daemon rejected internal PAM lease: {reason}");
        }
        ControlEvent::Shutdown => {
            lease.close()?;
            return Ok(());
        }
        ControlEvent::Command(other) => {
            bail!("unexpected command before lease acceptance: {other:?}");
        }
    }

    let environment =
        BackendEnvironment::new(&account, lease.environment(), &session_id, &runtime_dir)?;
    let mut supervisor = Supervisor {
        control,
        signals,
        config,
        account,
        backend,
        environment,
        manager: None,
        shutdown_requested: false,
    };
    supervisor.event_loop()?;
    supervisor.stop_manager()?;
    lease.close()?;
    let _ = supervisor.report(&HelperToDaemon::ShutdownComplete);
    Ok(())
}

struct Supervisor {
    control: SeqPacket,
    signals: SignalFd,
    config: Config,
    account: Account,
    backend: Backend,
    environment: BackendEnvironment,
    manager: Option<Manager>,
    shutdown_requested: bool,
}

struct Manager {
    child: Child,
    _state: InstanceState,
}

impl Supervisor {
    fn event_loop(&mut self) -> Result<()> {
        loop {
            if self.manager.is_some() {
                match self.wait_while_running()? {
                    RunningEvent::ManagerExited(status) => {
                        self.report(&HelperToDaemon::ManagerExited { status })?;
                    }
                    RunningEvent::Stop => self.stop_manager()?,
                    RunningEvent::Shutdown => return Ok(()),
                }
                continue;
            }

            match wait_for_command(&self.control, &self.signals)? {
                ControlEvent::Shutdown => return Ok(()),
                ControlEvent::Command(DaemonToHelper::StartManager { attempt }) => {
                    if let Err(error) = self.start_manager(attempt) {
                        if self.shutdown_requested {
                            return Ok(());
                        }
                        let message = bounded_message(&format!("{error:#}"));
                        self.report(&HelperToDaemon::StartFailed { message })?;
                    }
                }
                ControlEvent::Command(DaemonToHelper::StopManager) => {}
                ControlEvent::Command(DaemonToHelper::Shutdown) => return Ok(()),
                ControlEvent::Command(other) => {
                    bail!("unexpected helper command without a manager: {other:?}")
                }
            }
        }
    }

    fn start_manager(&mut self, attempt: u32) -> Result<()> {
        let state = InstanceState::create(self.account.uid, self.account.gid, attempt)?;
        let mut fifo = state.open_fifo_reader()?;
        let child = self.backend.spawn_run(
            &self.account,
            &self.environment,
            state.fifo(),
            state.directory(),
        )?;
        self.report(&HelperToDaemon::ManagerSpawned {
            pid: child.pid() as u32,
        })?;
        self.manager = Some(Manager {
            child,
            _state: state,
        });

        let deadline = Instant::now() + self.config.login_readiness_timeout();
        let payload = match self.read_payload(&mut fifo, deadline) {
            Ok(payload) => payload,
            Err(error) => {
                self.stop_manager()?;
                return Err(error);
            }
        };
        drop(fifo);
        self.report(&HelperToDaemon::ReadinessPayload {
            payload: payload.clone(),
        })?;

        let mut ready = match self
            .backend
            .spawn_ready(&self.account, &self.environment, &payload)
        {
            Ok(ready) => ready,
            Err(error) => {
                self.stop_manager()?;
                return Err(error);
            }
        };
        match self.wait_ready(&mut ready, deadline) {
            Ok(()) => {
                self.report(&HelperToDaemon::ReadySucceeded)?;
                Ok(())
            }
            Err(error) => {
                let _ = ready.signal(libc::SIGKILL);
                let _ = ready.wait();
                self.stop_manager()?;
                Err(error)
            }
        }
    }

    fn read_payload(&mut self, fifo: &mut std::fs::File, deadline: Instant) -> Result<String> {
        let mut frame = ReadinessFrame::default();
        loop {
            if let Some(status) = self.try_reap_manager()? {
                self.report(&HelperToDaemon::ManagerExited { status })?;
                bail!("manager exited before a complete readiness payload");
            }
            let timeout = remaining_milliseconds(deadline)?;
            let mut descriptors = self.poll_descriptors(Some(fifo.as_raw_fd()), None);
            let result = poll(&mut descriptors, timeout.min(100))?;
            if result == 0 {
                continue;
            }
            if shutdown_ready(&descriptors[0], &descriptors[1], &self.signals)? {
                self.shutdown_requested = true;
                bail!("shutdown requested during backend startup");
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                match self.control.recv::<DaemonToHelper>()? {
                    DaemonToHelper::Shutdown => {
                        self.shutdown_requested = true;
                        bail!("startup cancelled by daemon")
                    }
                    DaemonToHelper::StopManager => bail!("startup cancelled by daemon"),
                    other => bail!("unexpected command during backend startup: {other:?}"),
                }
            }

            let fifo_descriptor = &descriptors[2];
            if fifo_descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut chunk = [0_u8; 1024];
                match fifo.read(&mut chunk) {
                    Ok(0) if fifo_descriptor.revents & libc::POLLHUP != 0 => {
                        frame.eof()?;
                        unreachable!("completed frame returns before polling again")
                    }
                    Ok(0) => {}
                    Ok(count) => {
                        if let Some(payload) = frame.push(&chunk[..count])? {
                            return Ok(payload);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error).context("read readiness FIFO"),
                }
            }
        }
    }

    fn wait_ready(&mut self, ready: &mut Child, deadline: Instant) -> Result<()> {
        loop {
            if let Some(status) = self.try_reap_manager()? {
                self.report(&HelperToDaemon::ManagerExited { status })?;
                bail!("manager exited while ready action was running");
            }
            if let Some(status) = ready.try_wait()? {
                if status == ProcessStatus::Exited(0) {
                    if let Some(manager_status) = self.try_reap_manager()? {
                        self.report(&HelperToDaemon::ManagerExited {
                            status: manager_status,
                        })?;
                        bail!("manager exited as the ready action succeeded");
                    }
                    return Ok(());
                }
                bail!("backend ready action failed with {status}");
            }
            let timeout = remaining_milliseconds(deadline)?.min(100);
            let mut descriptors = self.poll_descriptors(None, ready.poll_fd());
            if poll(&mut descriptors, timeout)? == 0 {
                continue;
            }
            if shutdown_ready(&descriptors[0], &descriptors[1], &self.signals)? {
                self.shutdown_requested = true;
                bail!("shutdown requested during ready action");
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                match self.control.recv::<DaemonToHelper>()? {
                    DaemonToHelper::Shutdown => {
                        self.shutdown_requested = true;
                        bail!("startup cancelled by daemon")
                    }
                    DaemonToHelper::StopManager => bail!("startup cancelled by daemon"),
                    other => bail!("unexpected command during ready action: {other:?}"),
                }
            }
        }
    }

    fn wait_while_running(&mut self) -> Result<RunningEvent> {
        loop {
            if let Some(status) = self.try_reap_manager()? {
                return Ok(RunningEvent::ManagerExited(status));
            }
            let manager_fd = self
                .manager
                .as_ref()
                .and_then(|manager| manager.child.poll_fd());
            let mut descriptors = self.poll_descriptors(None, manager_fd);
            if poll(&mut descriptors, 100)? == 0 {
                continue;
            }
            if shutdown_ready(&descriptors[0], &descriptors[1], &self.signals)? {
                return Ok(RunningEvent::Shutdown);
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                return Ok(match self.control.recv::<DaemonToHelper>()? {
                    DaemonToHelper::StopManager => RunningEvent::Stop,
                    DaemonToHelper::Shutdown => RunningEvent::Shutdown,
                    other => bail!("unexpected command while manager is running: {other:?}"),
                });
            }
        }
    }

    fn stop_manager(&mut self) -> Result<()> {
        let Some(mut manager) = self.manager.take() else {
            return Ok(());
        };
        if let Some(status) = manager.child.try_wait()? {
            return self.report(&HelperToDaemon::ManagerExited { status });
        }

        match self
            .backend
            .spawn_stop(&self.account, &self.environment, manager.child.pid())
        {
            Ok(mut stop) => match stop.wait_timeout(self.config.graceful_stop_timeout())? {
                Some(ProcessStatus::Exited(0)) => {}
                Some(status) => {
                    eprintln!("elogind-usersv-supervisor: backend stop hook failed with {status}")
                }
                None => {
                    eprintln!("elogind-usersv-supervisor: backend stop hook timed out");
                    let _ = stop.signal(libc::SIGKILL);
                    let _ = stop.wait();
                }
            },
            Err(error) => {
                eprintln!("elogind-usersv-supervisor: cannot execute backend stop hook: {error:#}")
            }
        }

        let status = if let Some(status) = manager
            .child
            .wait_timeout(self.config.graceful_stop_timeout())?
        {
            status
        } else {
            let _ = manager.child.signal(libc::SIGTERM);
            if let Some(status) = manager
                .child
                .wait_timeout(self.config.forced_stop_timeout())?
            {
                status
            } else {
                let _ = manager.child.signal(libc::SIGKILL);
                manager.child.wait()?
            }
        };
        self.report(&HelperToDaemon::ManagerExited { status })
    }

    fn try_reap_manager(&mut self) -> Result<Option<ProcessStatus>> {
        let Some(manager) = &mut self.manager else {
            return Ok(None);
        };
        let status = manager.child.try_wait()?;
        if status.is_some() {
            self.manager = None;
        }
        Ok(status)
    }

    fn poll_descriptors(
        &self,
        extra_fd: Option<RawFd>,
        child_fd: Option<RawFd>,
    ) -> Vec<libc::pollfd> {
        let mut descriptors = vec![
            libc::pollfd {
                fd: self.control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: self.signals.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if let Some(fd) = extra_fd {
            descriptors.push(libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            });
        }
        if let Some(fd) = child_fd {
            descriptors.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        descriptors
    }

    fn report(&self, event: &HelperToDaemon) -> Result<()> {
        self.control.send(event).context("send helper event")
    }
}

enum RunningEvent {
    ManagerExited(ProcessStatus),
    Stop,
    Shutdown,
}

enum ControlEvent {
    Command(DaemonToHelper),
    Shutdown,
}

fn wait_for_command(control: &SeqPacket, signals: &SignalFd) -> Result<ControlEvent> {
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll(&mut descriptors, -1)?;
        if shutdown_ready(&descriptors[0], &descriptors[1], signals)? {
            return Ok(ControlEvent::Shutdown);
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            return Ok(ControlEvent::Command(control.recv()?));
        }
    }
}

fn shutdown_ready(
    control: &libc::pollfd,
    signal: &libc::pollfd,
    signals: &SignalFd,
) -> Result<bool> {
    if control.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Ok(true);
    }
    if signal.revents & libc::POLLIN != 0 {
        let _ = signals.received()?;
        return Ok(true);
    }
    Ok(false)
}

fn poll(descriptors: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<libc::c_int> {
    loop {
        // SAFETY: descriptors points to initialized pollfd records.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn remaining_milliseconds(deadline: Instant) -> Result<libc::c_int> {
    let now = Instant::now();
    if now >= deadline {
        bail!("backend readiness timed out");
    }
    Ok((deadline - now).as_millis().min(libc::c_int::MAX as u128) as libc::c_int)
}

fn bounded_message(message: &str) -> String {
    let message = message.replace(['\n', '\r', '\0'], " ");
    if message.len() <= 1024 {
        return message;
    }
    let mut end = 1024;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

struct Arguments {
    control_fd: RawFd,
    uid: libc::uid_t,
    config_path: PathBuf,
}

impl Arguments {
    fn parse() -> Result<Self> {
        let mut control_fd = None;
        let mut uid = None;
        let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--control-fd") => {
                    control_fd = Some(parse_value(&mut arguments, "control fd")?);
                }
                Some("--uid") => uid = Some(parse_value(&mut arguments, "UID")?),
                Some("--config") => {
                    config_path =
                        PathBuf::from(arguments.next().context("--config requires a path")?);
                }
                _ => bail!("unknown supervisor argument: {argument:?}"),
            }
        }
        let control_fd = control_fd.context("--control-fd is required")?;
        if control_fd < 3 {
            bail!("control fd must be at least 3");
        }
        Ok(Self {
            control_fd,
            uid: uid.context("--uid is required")?,
            config_path,
        })
    }
}

fn parse_value<T: std::str::FromStr>(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &'static str,
) -> Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    arguments
        .next()
        .with_context(|| format!("missing {name}"))?
        .to_str()
        .with_context(|| format!("{name} is not valid UTF-8"))?
        .parse()
        .with_context(|| format!("invalid {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_messages_remain_utf8() {
        let message = "é".repeat(600);
        let bounded = bounded_message(&message);
        assert!(bounded.len() <= 1024);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn expired_deadline_is_a_timeout() {
        assert!(
            remaining_milliseconds(Instant::now() - std::time::Duration::from_millis(1)).is_err()
        );
    }
}
