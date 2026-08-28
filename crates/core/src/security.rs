use std::{
    ffi::CString,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

use thiserror::Error;

pub fn verify_root_owned_file(
    path: &Path,
    require_executable: bool,
) -> Result<(), TrustedFileError> {
    if !path.is_absolute() {
        return Err(TrustedFileError::NotAbsolute);
    }
    let mut current = std::path::PathBuf::from("/");
    let mut found_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(component) => {
                found_component = true;
                current.push(component);
            }
            _ => return Err(TrustedFileError::InvalidComponent),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(TrustedFileError::Inspect)?;
        if metadata.file_type().is_symlink() {
            return Err(TrustedFileError::Symlink(current));
        }
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(TrustedFileError::UnsafeOwnership(current));
        }
        if current != path && !metadata.is_dir() {
            return Err(TrustedFileError::ParentNotDirectory(current));
        }
        if current == path {
            if !metadata.is_file() {
                return Err(TrustedFileError::NotRegular);
            }
            if require_executable && metadata.mode() & 0o111 == 0 {
                return Err(TrustedFileError::NotExecutable);
            }
        }
    }
    if !found_component {
        return Err(TrustedFileError::NotRegular);
    }
    Ok(())
}

pub fn verify_runtime_directory(path: &Path, uid: libc::uid_t) -> Result<(), RuntimePathError> {
    if !path.is_absolute() {
        return Err(RuntimePathError::NotAbsolute);
    }
    let descriptor = match openat2_no_symlinks(path) {
        Ok(descriptor) => descriptor,
        Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => walk_no_symlinks(path)?,
        Err(error) => return Err(RuntimePathError::Open(error)),
    };
    // SAFETY: zero is valid storage before fstat initializes it.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: descriptor is valid and metadata points to writable storage.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut metadata) } != 0 {
        return Err(RuntimePathError::Open(io::Error::last_os_error()));
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(RuntimePathError::NotDirectory);
    }
    if metadata.st_uid != uid {
        return Err(RuntimePathError::WrongOwner {
            expected: uid,
            actual: metadata.st_uid,
        });
    }
    Ok(())
}

fn openat2_no_symlinks(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: zero initializes all currently defined and future-reserved fields.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: path and how point to initialized input objects of the supplied size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    } as libc::c_int;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat2 returned a new uniquely owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn walk_no_symlinks(path: &Path) -> Result<OwnedFd, RuntimePathError> {
    // SAFETY: the static path is NUL terminated.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(RuntimePathError::Open(io::Error::last_os_error()));
    }
    // SAFETY: open returned a new uniquely owned descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(root) };
    let mut found_component = false;
    for component in path.components() {
        let Component::Normal(component) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(RuntimePathError::InvalidComponent);
        };
        found_component = true;
        let component =
            CString::new(component.as_bytes()).map_err(|_| RuntimePathError::InvalidComponent)?;
        // SAFETY: current and component are valid; O_NOFOLLOW rejects symlinks.
        let next = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if next < 0 {
            return Err(RuntimePathError::Open(io::Error::last_os_error()));
        }
        // SAFETY: openat returned a new uniquely owned descriptor.
        current = unsafe { OwnedFd::from_raw_fd(next) };
    }
    if !found_component {
        return Err(RuntimePathError::InvalidComponent);
    }
    Ok(current)
}

#[derive(Debug, Error)]
pub enum TrustedFileError {
    #[error("trusted file path is not absolute")]
    NotAbsolute,
    #[error("trusted file path contains an invalid component")]
    InvalidComponent,
    #[error("cannot inspect trusted file path: {0}")]
    Inspect(#[source] io::Error),
    #[error("trusted file path traverses symlink {0}")]
    Symlink(std::path::PathBuf),
    #[error("trusted path component has unsafe ownership or permissions: {0}")]
    UnsafeOwnership(std::path::PathBuf),
    #[error("trusted path parent is not a directory: {0}")]
    ParentNotDirectory(std::path::PathBuf),
    #[error("trusted file is not a regular file")]
    NotRegular,
    #[error("trusted executable does not have an execute bit")]
    NotExecutable,
}

#[derive(Debug, Error)]
pub enum RuntimePathError {
    #[error("runtime path is not absolute")]
    NotAbsolute,
    #[error("runtime path contains an invalid component")]
    InvalidComponent,
    #[error("cannot safely open runtime path: {0}")]
    Open(#[source] io::Error),
    #[error("runtime path is not a directory")]
    NotDirectory,
    #[error("runtime path is owned by UID {actual}, expected {expected}")]
    WrongOwner {
        expected: libc::uid_t,
        actual: libc::uid_t,
    },
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn accepts_owned_real_directory_and_rejects_symlink() {
        let directory = tempfile::tempdir().unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        verify_runtime_directory(directory.path(), uid).unwrap();

        let link = directory.path().parent().unwrap().join(format!(
            "elogind-usersv-security-link-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&link);
        symlink(directory.path(), &link).unwrap();
        assert!(verify_runtime_directory(&link, uid).is_err());
        std::fs::remove_file(link).unwrap();
    }

    #[test]
    fn rejects_wrong_owner_and_relative_paths() {
        let directory = tempfile::tempdir().unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert!(verify_runtime_directory(directory.path(), uid.wrapping_add(1)).is_err());
        assert!(verify_runtime_directory(Path::new("relative"), uid).is_err());
    }
}
