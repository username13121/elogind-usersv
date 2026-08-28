use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use elogind_usersv_protocol::ReadinessFrame;

fn backend() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/backends/backend-test")
}

struct RunningBackend {
    child: Child,
    reader: File,
    _temporary: tempfile::TempDir,
    config: PathBuf,
}

impl RunningBackend {
    fn start(mode: &str) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("state");
        let config = temporary.path().join("config");
        std::fs::create_dir(&state).unwrap();
        std::fs::create_dir(&config).unwrap();
        std::fs::write(config.join("mode"), format!("{mode}\n")).unwrap();
        let fifo = temporary.path().join("ready");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_c is NUL terminated and points into a private temporary directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&fifo)
            .unwrap();
        let child = backend_command()
            .arg("run")
            .arg(&fifo)
            .arg(&state)
            .arg(&config)
            .spawn()
            .unwrap();
        Self {
            child,
            reader,
            _temporary: temporary,
            config,
        }
    }

    fn payload(&mut self, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        let mut frame = ReadinessFrame::default();
        loop {
            let mut bytes = [0_u8; 8192];
            match self.reader.read(&mut bytes) {
                Ok(0) => {}
                Ok(count) => match frame.push(&bytes[..count]) {
                    Ok(Some(payload)) => return Ok(payload),
                    Ok(None) => {}
                    Err(error) => return Err(error.to_string()),
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
            if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                return frame
                    .eof()
                    .map(|()| unreachable!())
                    .map_err(|error| format!("{error}; manager {status}"));
            }
            if Instant::now() >= deadline {
                return Err("readiness timeout".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn ready(&self, payload: &str) -> ExitStatus {
        backend_command()
            .arg("ready")
            .arg(payload)
            .status()
            .unwrap()
    }

    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_some() {
            return;
        }
        let status = backend_command()
            .arg("stop")
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("test backend ignored graceful stop");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RunningBackend {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn backend_command() -> Command {
    let mut command = Command::new(backend());
    command
        .env_clear()
        .env("HOME", "/")
        .env("USER", "test")
        .env("LOGNAME", "test")
        .env("SHELL", "/bin/sh")
        .env("PATH", "/usr/bin:/bin")
        .env("UID", "1000")
        .env("GID", "1000")
        .env("XDG_RUNTIME_DIR", "/tmp")
        .env("XDG_SESSION_ID", "test")
        .env("XDG_SESSION_CLASS", "background")
        .env("XDG_SESSION_TYPE", "unspecified")
        .env("XDG_CONFIG_HOME", "/tmp/config")
        .env("XDG_DATA_HOME", "/tmp/data")
        .env("XDG_STATE_HOME", "/tmp/state")
        .env("XDG_CACHE_HOME", "/tmp/cache")
        .env("ELOGIND_USERSV_BACKEND_PROTOCOL", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
fn successful_backend_obeys_run_ready_stop_contract() {
    let mut backend = RunningBackend::start("success");
    let payload = backend.payload(Duration::from_secs(2)).unwrap();
    assert_eq!(payload, "test-ready");
    assert!(backend.ready(&payload).success());
    assert!(backend.child.try_wait().unwrap().is_none());
    backend.stop();
}

#[test]
fn ready_exit_status_is_meaningful() {
    let mut backend = RunningBackend::start("ready-fail");
    let payload = backend.payload(Duration::from_secs(2)).unwrap();
    assert_eq!(payload, "ready-fail");
    assert!(!backend.ready(&payload).success());
    backend.stop();
}

#[test]
fn malformed_and_early_exit_modes_fail_closed() {
    for mode in ["empty", "no-nul", "multiple", "oversized", "manager-exit"] {
        let mut backend = RunningBackend::start(mode);
        assert!(
            backend.payload(Duration::from_secs(2)).is_err(),
            "mode {mode} unexpectedly became ready (config {})",
            backend.config.display()
        );
    }
}

#[test]
fn missing_notification_times_out_with_manager_alive() {
    let mut backend = RunningBackend::start("timeout");
    assert_eq!(
        backend.payload(Duration::from_millis(150)),
        Err("readiness timeout".into())
    );
    assert!(backend.child.try_wait().unwrap().is_none());
    backend.stop();
}
