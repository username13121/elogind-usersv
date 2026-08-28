use std::{
    ffi::{CString, OsStr, c_char, c_int},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use elogind_usersv_core::account::Account;
use elogind_usersv_protocol::ProcessStatus;

pub struct Backend {
    path: PathBuf,
    path_c: CString,
    config_dir: PathBuf,
}

impl Backend {
    pub fn load(path: PathBuf, config_dir: PathBuf) -> Result<Self> {
        verify_trusted_path(&path, false).context("backend executable is not trusted")?;
        verify_trusted_path(&config_dir, true)
            .context("backend configuration directory is not trusted")?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("backend must be a root-owned regular file not writable by group or other");
        }
        if metadata.mode() & 0o111 == 0 {
            bail!("backend is not executable");
        }
        let path_c = path_cstring(&path)?;
        Ok(Self {
            path,
            path_c,
            config_dir,
        })
    }

    pub fn spawn_run(
        &self,
        account: &Account,
        environment: &BackendEnvironment,
        ready_fifo: &Path,
        state_dir: &Path,
    ) -> Result<Child> {
        self.spawn(
            account,
            environment,
            &[
                OsStr::new("run"),
                ready_fifo.as_os_str(),
                state_dir.as_os_str(),
                self.config_dir.as_os_str(),
            ],
        )
    }

    pub fn spawn_ready(
        &self,
        account: &Account,
        environment: &BackendEnvironment,
        payload: &str,
    ) -> Result<Child> {
        self.spawn(
            account,
            environment,
            &[OsStr::new("ready"), OsStr::new(payload)],
        )
    }

    pub fn spawn_stop(
        &self,
        account: &Account,
        environment: &BackendEnvironment,
        manager_pid: libc::pid_t,
    ) -> Result<Child> {
        let pid = manager_pid.to_string();
        self.spawn(
            account,
            environment,
            &[OsStr::new("stop"), OsStr::new(&pid)],
        )
    }

    fn spawn(
        &self,
        account: &Account,
        environment: &BackendEnvironment,
        arguments: &[&OsStr],
    ) -> Result<Child> {
        // Recheck immediately before every execution. Trusted parent
        // directories make the subsequent pathname exec resistant to races
        // while retaining support for shebang executables.
        verify_trusted_path(&self.path, false)?;
        let mut c_arguments = Vec::with_capacity(arguments.len() + 1);
        c_arguments.push(self.path_c.clone());
        for argument in arguments {
            c_arguments.push(
                CString::new(argument.as_bytes())
                    .with_context(|| format!("backend argument contains NUL: {argument:?}"))?,
            );
        }
        let mut argv: Vec<_> = c_arguments.iter().map(|value| value.as_ptr()).collect();
        argv.push(ptr::null());
        let mut envp: Vec<_> = environment
            .values
            .iter()
            .map(|value| value.as_ptr())
            .collect();
        envp.push(ptr::null());
        let home = path_cstring(&account.home)?;
        let expected_parent = unsafe { libc::getpid() };

        // The helper is single-threaded, so no other thread can hold libc or
        // allocator locks across this fork.
        // SAFETY: fork has no pointer arguments.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error()).context("fork backend action");
        }
        if pid == 0 {
            // SAFETY: all pointers were prepared before fork and remain valid
            // in this private child address space until exec or _exit.
            unsafe {
                child_exec(
                    expected_parent,
                    account.uid,
                    account.gid,
                    home.as_ptr(),
                    self.path_c.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                )
            }
        }
        Ok(Child::new(pid))
    }
}

pub struct BackendEnvironment {
    values: Vec<CString>,
}

impl BackendEnvironment {
    pub fn new(
        account: &Account,
        pam_environment: &std::collections::HashMap<String, String>,
        session_id: &str,
        runtime_dir: &str,
    ) -> Result<Self> {
        let home = account
            .home
            .to_str()
            .context("home directory is not valid UTF-8")?;
        let shell = account.shell.to_str().context("shell is not valid UTF-8")?;
        let mut entries = vec![
            ("HOME", home.to_owned()),
            ("USER", account.name.clone()),
            ("LOGNAME", account.name.clone()),
            ("SHELL", shell.to_owned()),
            ("PATH", "/usr/local/bin:/usr/bin:/bin".into()),
            ("UID", account.uid.to_string()),
            ("GID", account.gid.to_string()),
            ("XDG_RUNTIME_DIR", runtime_dir.to_owned()),
            ("XDG_SESSION_ID", session_id.to_owned()),
            ("XDG_SESSION_CLASS", "background".into()),
            ("XDG_SESSION_TYPE", "unspecified".into()),
            (
                "XDG_CONFIG_HOME",
                xdg_path(pam_environment, "XDG_CONFIG_HOME", home, ".config"),
            ),
            (
                "XDG_DATA_HOME",
                xdg_path(pam_environment, "XDG_DATA_HOME", home, ".local/share"),
            ),
            (
                "XDG_STATE_HOME",
                xdg_path(pam_environment, "XDG_STATE_HOME", home, ".local/state"),
            ),
            (
                "XDG_CACHE_HOME",
                xdg_path(pam_environment, "XDG_CACHE_HOME", home, ".cache"),
            ),
            ("ELOGIND_USERSV_BACKEND_PROTOCOL", "1".into()),
        ];
        let mut values = Vec::with_capacity(entries.len());
        for (name, value) in entries.drain(..) {
            if value.contains(['\n', '\r']) {
                bail!("backend environment {name} contains a line break");
            }
            values.push(CString::new(format!("{name}={value}"))?);
        }
        Ok(Self { values })
    }
}

fn xdg_path(
    pam_environment: &std::collections::HashMap<String, String>,
    name: &str,
    home: &str,
    suffix: &str,
) -> String {
    pam_environment
        .get(name)
        .filter(|value| Path::new(value).is_absolute())
        .cloned()
        .unwrap_or_else(|| format!("{home}/{suffix}"))
}

pub struct Child {
    pid: libc::pid_t,
    pidfd: Option<OwnedFd>,
    reaped: bool,
}

impl Child {
    fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            pidfd: pidfd_open(pid).ok(),
            reaped: false,
        }
    }

    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn poll_fd(&self) -> Option<RawFd> {
        self.pidfd.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ProcessStatus>> {
        if self.reaped {
            return Ok(None);
        }
        let mut status = 0;
        // SAFETY: status points to writable storage and pid is our child.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(None);
        }
        self.reaped = true;
        Ok(Some(process_status(status)))
    }

    pub fn wait(&mut self) -> io::Result<ProcessStatus> {
        if self.reaped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child already reaped",
            ));
        }
        let mut status = 0;
        loop {
            // SAFETY: status points to writable storage and pid is our child.
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                return Ok(process_status(status));
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
        }
    }

    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ProcessStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let milliseconds = (deadline - now).as_millis().min(100) as libc::c_int;
            if let Some(pidfd) = self.poll_fd() {
                let mut descriptor = libc::pollfd {
                    fd: pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: descriptor points to one initialized pollfd.
                let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err(io::Error::last_os_error());
                }
            } else {
                std::thread::sleep(Duration::from_millis(milliseconds as u64));
            }
        }
    }

    pub fn signal(&self, signal: c_int) -> io::Result<()> {
        if let Some(pidfd) = &self.pidfd {
            // SAFETY: pidfd is valid and null siginfo with flags zero is supported.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    signal,
                    ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOSYS) {
                return Err(error);
            }
        }
        // The PID remains reserved until this parent reaps its child, so the
        // fallback cannot signal a reused PID.
        // SAFETY: kill has no pointer arguments.
        if unsafe { libc::kill(self.pid, signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.signal(libc::SIGKILL);
            let _ = self.wait();
        }
    }
}

unsafe fn child_exec(
    expected_parent: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: *const c_char,
    executable: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> ! {
    // SAFETY: this function runs in the single-threaded fork child.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
            || libc::getppid() != expected_parent
        {
            libc::_exit(125);
        }
        let empty_mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, ptr::null_mut()) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(uid, uid, uid) != 0
        {
            libc::_exit(126);
        }
        if libc::chdir(home) != 0 && libc::chdir(c"/".as_ptr()) != 0 {
            libc::_exit(126);
        }
        libc::umask(0o022);
        close_unrelated_fds();
        libc::execve(executable, argv, envp);
        libc::_exit(127);
    }
}

unsafe fn close_unrelated_fds() {
    // SAFETY: close_range has no pointer arguments.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
    if result == 0 {
        return;
    }
    for fd in 3..65_536 {
        // SAFETY: closing an invalid descriptor is harmless.
        unsafe { libc::close(fd) };
    }
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open has no pointer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: syscall returned a new uniquely owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn process_status(status: c_int) -> ProcessStatus {
    if libc::WIFEXITED(status) {
        ProcessStatus::Exited(libc::WEXITSTATUS(status) as u32)
    } else if libc::WIFSIGNALED(status) {
        ProcessStatus::Signaled(libc::WTERMSIG(status) as u32)
    } else {
        ProcessStatus::Other(status as u32)
    }
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains NUL: {}", path.display()))
}

fn verify_trusted_path(path: &Path, require_directory: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("path is not absolute: {}", path.display());
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(component) => current.push(component),
            _ => bail!("path contains a non-normal component: {}", path.display()),
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            bail!("path traverses a symlink: {}", current.display());
        }
        if current != path
            && (!metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0)
        {
            bail!(
                "parent directory must be root-owned and not writable by group or other: {}",
                current.display()
            );
        }
    }
    if require_directory {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "configuration path must be a root-owned directory not writable by group or other: {}",
                path.display()
            );
        }
    }
    Ok(())
}
