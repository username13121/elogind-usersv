use std::{
    ffi::{CStr, CString, c_char, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    time::Duration,
};

use elogind_usersv_core::{
    config::DEFAULT_CONTROL_SOCKET,
    ipc::{MessageIoError, SeqPacket},
};
use elogind_usersv_protocol::{PamReply, PamRequest};

const PAM_SUCCESS: c_int = 0;
const PAM_SESSION_ERR: c_int = 14;
const DEFAULT_TIMEOUT_SECONDS: u64 = 35;
const MAX_PAM_ARGUMENTS: c_int = 32;

type PamHandle = std::ffi::c_void;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, format: *const c_char, ...);
}

#[derive(Clone, Copy, Debug)]
struct ModuleOptions {
    timeout: Duration,
}

impl Default for ModuleOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        }
    }
}

/// Wait until the daemon confirms that the service manager for the login1
/// session is ready. This entry point must be placed after pam_elogind.
///
/// # Safety
///
/// This function must only be called by PAM with a valid `pam_handle_t` and
/// an argument vector containing `argc` valid C string pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: PAM owns the handle and argument vector for this invocation.
        unsafe { open_session(pamh, argc, argv) }
    })) {
        Ok(status) => status,
        Err(_) => {
            log_error(pamh, "internal panic while waiting for the user manager");
            PAM_SESSION_ERR
        }
    }
}

/// Logout is inferred exclusively from login1's session inventory.
///
/// # Safety
///
/// This function must only be called by PAM using its module ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

unsafe fn open_session(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    if pamh.is_null() {
        return PAM_SESSION_ERR;
    }
    // SAFETY: the caller provides the PAM-owned argument vector.
    let options = match unsafe { parse_options(argc, argv) } {
        Ok(options) => options,
        Err(message) => {
            log_error(pamh, message);
            return PAM_SESSION_ERR;
        }
    };

    let mut user = std::ptr::null();
    // SAFETY: pamh is non-null and PAM writes one borrowed string pointer.
    let status = unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) };
    if status != PAM_SUCCESS || user.is_null() {
        log_error(pamh, "PAM_USER is unavailable");
        return PAM_SESSION_ERR;
    }
    // Requiring a bounded, valid username catches broken PAM applications.
    // Identity is still resolved authoritatively from login1 by the daemon.
    // SAFETY: successful pam_get_user returned a NUL-terminated borrowed string.
    let Ok(user) = unsafe { CStr::from_ptr(user) }.to_str() else {
        log_error(pamh, "PAM_USER is not valid UTF-8");
        return PAM_SESSION_ERR;
    };
    if user.is_empty() || user.len() > 256 {
        log_error(pamh, "PAM_USER has an invalid length");
        return PAM_SESSION_ERR;
    }

    // SAFETY: pamh is valid for the duration of the PAM call.
    let session_id = match unsafe { pam_environment(pamh, c"XDG_SESSION_ID") } {
        Ok(value) => value,
        Err(message) => {
            log_error(pamh, message);
            return PAM_SESSION_ERR;
        }
    };
    // SAFETY: pamh is valid for the duration of the PAM call.
    let runtime_dir = match unsafe { pam_environment(pamh, c"XDG_RUNTIME_DIR") } {
        Ok(value) => value,
        Err(message) => {
            log_error(pamh, message);
            return PAM_SESSION_ERR;
        }
    };
    if !Path::new(&runtime_dir).is_absolute() {
        log_error(pamh, "XDG_RUNTIME_DIR is not absolute");
        return PAM_SESSION_ERR;
    }

    match request_ready(&session_id, &runtime_dir, options.timeout) {
        Ok(()) => PAM_SUCCESS,
        Err(PamClientError::Daemon(code)) => {
            log_error(
                pamh,
                &format!("user manager was not ready (daemon error code {code})"),
            );
            PAM_SESSION_ERR
        }
        Err(PamClientError::Transport(error)) => {
            log_error(pamh, &format!("cannot wait for user manager: {error}"));
            PAM_SESSION_ERR
        }
    }
}

fn request_ready(
    session_id: &str,
    runtime_dir: &str,
    timeout: Duration,
) -> Result<(), PamClientError> {
    let socket = SeqPacket::connect(DEFAULT_CONTROL_SOCKET)?;
    socket.set_timeouts(timeout)?;
    socket.send(&PamRequest::EnsureManagerReady {
        session_id: session_id.to_owned(),
        runtime_dir: runtime_dir.to_owned(),
    })?;
    match socket.recv::<PamReply>()? {
        PamReply::Ready => Ok(()),
        PamReply::Error { code, .. } => Err(PamClientError::Daemon(code as u16)),
    }
}

unsafe fn pam_environment(
    pamh: *mut PamHandle,
    name: &'static CStr,
) -> Result<String, &'static str> {
    // SAFETY: pamh is valid and name is NUL terminated.
    let value = unsafe { pam_getenv(pamh, name.as_ptr()) };
    if value.is_null() {
        return Err(match name.to_bytes() {
            b"XDG_SESSION_ID" => "XDG_SESSION_ID is unavailable; pam_elogind must run first",
            _ => "XDG_RUNTIME_DIR is unavailable; pam_elogind must run first",
        });
    }
    // SAFETY: PAM environment values are NUL-terminated and borrowed from pamh.
    let value = unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| "PAM environment value is not valid UTF-8")?;
    if value.is_empty() {
        return Err("required PAM environment value is empty");
    }
    Ok(value.to_owned())
}

unsafe fn parse_options(
    argc: c_int,
    argv: *const *const c_char,
) -> Result<ModuleOptions, &'static str> {
    if !(0..=MAX_PAM_ARGUMENTS).contains(&argc) || (argc > 0 && argv.is_null()) {
        return Err("invalid PAM module argument vector");
    }
    let mut options = ModuleOptions::default();
    for index in 0..argc as isize {
        // SAFETY: PAM guarantees argc readable pointers in argv.
        let argument = unsafe { *argv.offset(index) };
        if argument.is_null() {
            return Err("null PAM module argument");
        }
        // SAFETY: PAM module arguments are NUL-terminated strings.
        let argument = unsafe { CStr::from_ptr(argument) }
            .to_str()
            .map_err(|_| "PAM module argument is not valid UTF-8")?;
        let Some(value) = argument.strip_prefix("timeout=") else {
            return Err("unsupported pam_elogind_usersv option");
        };
        let seconds: u64 = value
            .parse()
            .map_err(|_| "invalid pam_elogind_usersv timeout")?;
        if !(1..=600).contains(&seconds) {
            return Err("pam_elogind_usersv timeout must be between 1 and 600 seconds");
        }
        options.timeout = Duration::from_secs(seconds);
    }
    Ok(options)
}

fn log_error(pamh: *mut PamHandle, message: &str) {
    let sanitized = message.replace(['\n', '\r'], " ");
    let Ok(message) = CString::new(sanitized) else {
        return;
    };
    // SAFETY: the format is constant and message is a matching C string argument.
    unsafe { pam_syslog(pamh, libc::LOG_ERR, c"%s".as_ptr(), message.as_ptr()) };
}

#[derive(Debug)]
enum PamClientError {
    Transport(MessageIoError),
    Daemon(u16),
}

impl std::fmt::Display for PamClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Daemon(code) => write!(formatter, "daemon error {code}"),
        }
    }
}

impl From<std::io::Error> for PamClientError {
    fn from(error: std::io::Error) -> Self {
        Self::Transport(MessageIoError::Io(error))
    }
}

impl From<MessageIoError> for PamClientError {
    fn from(error: MessageIoError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, ptr};

    #[test]
    fn parses_bounded_timeout() {
        let argument = CString::new("timeout=60").unwrap();
        let arguments = [argument.as_ptr()];
        // SAFETY: arguments contains one valid C string pointer.
        let options = unsafe { parse_options(1, arguments.as_ptr()) }.unwrap();
        assert_eq!(options.timeout, Duration::from_secs(60));
    }

    #[test]
    fn rejects_unknown_and_unbounded_options() {
        for argument in ["debug", "timeout=0", "timeout=601", "timeout=bad"] {
            let argument = CString::new(argument).unwrap();
            let arguments = [argument.as_ptr()];
            // SAFETY: arguments contains one valid C string pointer.
            assert!(unsafe { parse_options(1, arguments.as_ptr()) }.is_err());
        }
        // SAFETY: zero arguments permits a null argument vector.
        assert!(unsafe { parse_options(0, ptr::null()) }.is_ok());
    }
}
