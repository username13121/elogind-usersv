use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use elogind_usersv_core::config::DEFAULT_RUNTIME_DIRECTORY;

pub fn prepare_runtime() -> Result<()> {
    let root = Path::new(DEFAULT_RUNTIME_DIRECTORY);
    ensure_root_directory(root, 0o755)?;
    ensure_root_directory(&root.join("locks"), 0o700)?;
    ensure_root_directory(&root.join("instances"), 0o711)?;
    Ok(())
}

pub struct UserLock {
    _file: File,
}

impl UserLock {
    pub fn acquire(uid: libc::uid_t) -> Result<Self> {
        let path = Path::new(DEFAULT_RUNTIME_DIRECTORY)
            .join("locks")
            .join(uid.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("open per-UID lock {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!("unsafe per-UID lock metadata at {}", path.display());
        }
        // Wait for an orphaned old helper to finish rather than overlap it.
        loop {
            // SAFETY: file is a valid descriptor and flock has no pointers.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("lock per-UID supervisor lock");
            }
        }
        Ok(Self { _file: file })
    }
}

pub struct InstanceState {
    directory: PathBuf,
    fifo: PathBuf,
}

impl InstanceState {
    pub fn create(uid: libc::uid_t, gid: libc::gid_t, attempt: u32) -> Result<Self> {
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        let directory = Path::new(DEFAULT_RUNTIME_DIRECTORY)
            .join("instances")
            .join(format!("{uid}-{pid}-{attempt}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .with_context(|| format!("create manager state directory {}", directory.display()))?;
        let directory_c = path_cstring(&directory)?;
        // SAFETY: path is NUL terminated and was just created under a root-owned parent.
        if unsafe { libc::chown(directory_c.as_ptr(), uid, gid) } != 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_dir(&directory);
            return Err(error).context("chown manager state directory");
        }

        let fifo = directory.join("ready");
        let fifo_c = path_cstring(&fifo)?;
        // SAFETY: path is NUL terminated and parent is the new state directory.
        if unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) } != 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_dir_all(&directory);
            return Err(error).context("create readiness FIFO");
        }
        // SAFETY: path is NUL terminated and names the FIFO just created.
        if unsafe { libc::chown(fifo_c.as_ptr(), uid, gid) } != 0 {
            let error = io::Error::last_os_error();
            let _ = std::fs::remove_dir_all(&directory);
            return Err(error).context("chown readiness FIFO");
        }
        Ok(Self { directory, fifo })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn fifo(&self) -> &Path {
        &self.fifo
    }

    pub fn open_fifo_reader(&self) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.fifo)
            .context("open readiness FIFO")
    }
}

impl Drop for InstanceState {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.directory) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "elogind-usersv-supervisor: cannot remove state directory {}: {error}",
                    self.directory.display()
                );
            }
        }
    }
}

pub struct SignalFd(OwnedFd);

impl SignalFd {
    pub fn install() -> Result<Self> {
        // SAFETY: zero is valid storage before sigemptyset initializes it.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: mask points to writable sigset storage.
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGTERM);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGHUP);
        }
        // SAFETY: mask is initialized; no old mask is requested.
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error()).context("block termination signals");
        }
        // SAFETY: mask is initialized and flags are valid.
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("create signalfd");
        }
        // SAFETY: signalfd returned a new uniquely owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub fn received(&self) -> io::Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::signalfd_siginfo>::uninit();
        // SAFETY: info has enough writable storage for one signal record.
        let result = unsafe {
            libc::read(
                self.as_raw_fd(),
                info.as_mut_ptr().cast(),
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(result as usize == std::mem::size_of::<libc::signalfd_siginfo>())
    }
}

fn ensure_root_directory(path: &Path, mode: u32) -> Result<()> {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        bail!(
            "unsafe root runtime directory metadata at {}",
            path.display()
        );
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains NUL: {}", path.display()))
}
