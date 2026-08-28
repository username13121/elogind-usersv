use std::{
    ffi::{CStr, OsString},
    io,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

impl Account {
    pub fn is_nobody(&self) -> bool {
        self.uid == 65_534 || self.name == "nobody"
    }
}

pub fn resolve_uid(uid: libc::uid_t) -> Result<Account, AccountError> {
    // SAFETY: sysconf has no pointer arguments.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![
        0_u8;
        if suggested > 0 {
            suggested as usize
        } else {
            16 * 1024
        }
    ];
    // SAFETY: zero is a valid initial state for passwd output storage.
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers reference valid writable storage for the specified sizes.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(AccountError::Lookup(io::Error::from_raw_os_error(status)));
    }
    if result.is_null() {
        return Err(AccountError::NotFound(uid));
    }

    let name = required_utf8(passwd.pw_name, "username")?;
    let home = required_path(passwd.pw_dir, "home directory")?;
    let shell = required_path(passwd.pw_shell, "shell")?;
    if !home.is_absolute() {
        return Err(AccountError::Invalid("home directory is not absolute"));
    }
    if !shell.is_absolute() {
        return Err(AccountError::Invalid("shell is not absolute"));
    }

    Ok(Account {
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
        name,
        home,
        shell,
    })
}

pub fn login_defs_uid_min(path: impl AsRef<std::path::Path>) -> libc::uid_t {
    let Ok(source) = std::fs::read_to_string(path) else {
        return 1000;
    };
    source
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            let mut fields = line.split_whitespace();
            if fields.next()? != "UID_MIN" {
                return None;
            }
            fields.next()?.parse().ok()
        })
        .next()
        .unwrap_or(1000)
}

fn required_utf8(
    pointer: *const libc::c_char,
    field: &'static str,
) -> Result<String, AccountError> {
    if pointer.is_null() {
        return Err(AccountError::Invalid(field));
    }
    // SAFETY: NSS returned this pointer as part of a successful passwd record.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.is_empty() {
        return Err(AccountError::Invalid(field));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| AccountError::Invalid(field))
}

fn required_path(
    pointer: *const libc::c_char,
    field: &'static str,
) -> Result<PathBuf, AccountError> {
    if pointer.is_null() {
        return Err(AccountError::Invalid(field));
    }
    // SAFETY: NSS returned this pointer as part of a successful passwd record.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.is_empty() {
        return Err(AccountError::Invalid(field));
    }
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("NSS lookup failed: {0}")]
    Lookup(#[source] io::Error),
    #[error("UID {0} was not found through NSS")]
    NotFound(libc::uid_t),
    #[error("invalid NSS account: {0}")]
    Invalid(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_current_account() {
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let account = resolve_uid(uid).unwrap();
        assert_eq!(account.uid, uid);
        assert!(!account.name.is_empty());
        assert!(account.home.is_absolute());
    }

    #[test]
    fn reads_uid_min_and_ignores_comments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("login.defs");
        std::fs::write(&path, "# UID_MIN 7\n UID_MIN 2000 # local policy\n").unwrap();
        assert_eq!(login_defs_uid_min(path), 2000);
    }

    #[test]
    fn uid_min_has_conservative_fallback() {
        assert_eq!(login_defs_uid_min("/definitely/not/present"), 1000);
    }
}
