use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr,
};

use anyhow::{Context, Result, bail};
use elogind_usersv_core::{account::Account, config::INTERNAL_PAM_SERVICE};

const PAM_SUCCESS: c_int = 0;
const PAM_SILENT: c_int = 0x8000;
const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_DELETE_CRED: c_int = 0x0004;
const PAM_CONV_ERR: c_int = 19;

type PamHandle = c_void;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConversation {
    conv: Option<
        unsafe extern "C" fn(
            c_int,
            *mut *const PamMessage,
            *mut *mut PamResponse,
            *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        conversation: *const PamConversation,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int;
    fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
    fn pam_getenvlist(pamh: *mut PamHandle) -> *mut *mut c_char;
    fn pam_setcred(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_open_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_close_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_strerror(pamh: *mut PamHandle, status: c_int) -> *const c_char;
}

pub struct PamLease {
    handle: *mut PamHandle,
    opened: bool,
    ended: bool,
    environment: HashMap<String, String>,
}

impl PamLease {
    pub fn open(account: &Account) -> Result<Self> {
        let service = CString::new(INTERNAL_PAM_SERVICE).unwrap();
        let user = CString::new(account.name.as_str()).context("username contains NUL")?;
        let conversation = PamConversation {
            conv: Some(reject_conversation),
            appdata_ptr: ptr::null_mut(),
        };
        let mut handle = ptr::null_mut();
        // SAFETY: all pointers are valid for the duration of pam_start.
        let status =
            unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conversation, &mut handle) };
        check(handle, status, "pam_start")?;

        let mut lease = Self {
            handle,
            opened: false,
            ended: false,
            environment: HashMap::new(),
        };
        lease.putenv("XDG_SESSION_CLASS=background")?;
        lease.putenv("XDG_SESSION_TYPE=unspecified")?;

        // The helper is single-user and remains root; changing supplementary
        // groups here avoids NSS work in backend children after fork.
        // SAFETY: user is a valid C string and account.gid came from NSS.
        if unsafe { libc::initgroups(user.as_ptr(), account.gid) } != 0 {
            bail!("initgroups failed: {}", std::io::Error::last_os_error());
        }
        // SAFETY: handle remains owned by lease.
        check(
            lease.handle,
            unsafe { pam_setcred(lease.handle, PAM_ESTABLISH_CRED) },
            "pam_setcred(PAM_ESTABLISH_CRED)",
        )?;
        // SAFETY: handle remains owned by lease.
        check(
            lease.handle,
            unsafe { pam_open_session(lease.handle, 0) },
            "pam_open_session",
        )?;
        lease.opened = true;
        lease.environment = lease.read_environment()?;
        Ok(lease)
    }

    pub fn required(&self, name: &str) -> Result<&str> {
        self.environment
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("internal PAM session did not provide {name}"))
    }

    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    pub fn close(mut self) -> Result<()> {
        let result = self.close_inner();
        self.ended = true;
        result
    }

    fn putenv(&mut self, assignment: &str) -> Result<()> {
        let assignment = CString::new(assignment).unwrap();
        // SAFETY: handle is valid and assignment is NUL terminated.
        check(
            self.handle,
            unsafe { pam_putenv(self.handle, assignment.as_ptr()) },
            "pam_putenv",
        )
    }

    fn read_environment(&self) -> Result<HashMap<String, String>> {
        let mut environment = HashMap::new();
        // SAFETY: handle is valid. Linux-PAM returns a calloc-allocated list.
        let list = unsafe { pam_getenvlist(self.handle) };
        if list.is_null() {
            return Ok(environment);
        }
        let mut cursor = list;
        loop {
            // SAFETY: cursor points within the null-terminated pointer list.
            let assignment = unsafe { *cursor };
            if assignment.is_null() {
                break;
            }
            // SAFETY: each list item is a NUL-terminated allocated C string.
            let bytes = unsafe { CStr::from_ptr(assignment) }.to_bytes();
            if let Some(separator) = bytes.iter().position(|byte| *byte == b'=') {
                let name = std::str::from_utf8(&bytes[..separator]);
                let value = std::str::from_utf8(&bytes[separator + 1..]);
                if let (Ok(name), Ok(value)) = (name, value) {
                    environment.insert(name.to_owned(), value.to_owned());
                }
            }
            // SAFETY: Linux-PAM documents that callers free every list item.
            unsafe { libc::free(assignment.cast()) };
            // SAFETY: cursor currently points to a non-null list element.
            cursor = unsafe { cursor.add(1) };
        }
        // SAFETY: list was allocated by Linux-PAM for the caller.
        unsafe { libc::free(list.cast()) };
        Ok(environment)
    }

    fn close_inner(&mut self) -> Result<()> {
        let mut first_error = None;
        if self.opened {
            // SAFETY: handle is valid and this lease opened the session.
            let status = unsafe { pam_close_session(self.handle, 0) };
            if status != PAM_SUCCESS {
                first_error = Some(pam_error(self.handle, status, "pam_close_session"));
            }
            self.opened = false;
        }
        // SAFETY: handle is valid until pam_end.
        let status = unsafe { pam_setcred(self.handle, PAM_DELETE_CRED | PAM_SILENT) };
        if status != PAM_SUCCESS && first_error.is_none() {
            first_error = Some(pam_error(
                self.handle,
                status,
                "pam_setcred(PAM_DELETE_CRED)",
            ));
        }
        // SAFETY: this consumes the PAM transaction.
        let status = unsafe {
            pam_end(
                self.handle,
                first_error.as_ref().map_or(PAM_SUCCESS, |_| 14),
            )
        };
        if status != PAM_SUCCESS && first_error.is_none() {
            first_error = Some(anyhow::anyhow!("pam_end returned status {status}"));
        }
        self.ended = true;
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for PamLease {
    fn drop(&mut self) {
        if !self.ended {
            if let Err(error) = self.close_inner() {
                eprintln!("elogind-usersv-supervisor: failed to close PAM lease: {error:#}");
            }
        }
    }
}

unsafe extern "C" fn reject_conversation(
    _num_msg: c_int,
    _messages: *mut *const PamMessage,
    response: *mut *mut PamResponse,
    _appdata: *mut c_void,
) -> c_int {
    if !response.is_null() {
        // SAFETY: PAM supplied response as writable output storage.
        unsafe { *response = ptr::null_mut() };
    }
    PAM_CONV_ERR
}

fn check(handle: *mut PamHandle, status: c_int, operation: &'static str) -> Result<()> {
    if status == PAM_SUCCESS {
        Ok(())
    } else {
        Err(pam_error(handle, status, operation))
    }
}

fn pam_error(handle: *mut PamHandle, status: c_int, operation: &'static str) -> anyhow::Error {
    // SAFETY: pam_strerror accepts a possibly-null handle and returns static storage.
    let message = unsafe { pam_strerror(handle, status) };
    let message = if message.is_null() {
        "unknown PAM error".into()
    } else {
        // SAFETY: pam_strerror returned a NUL-terminated string.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    };
    anyhow::anyhow!("{operation} failed ({status}): {message}")
}

/// Reads a single PAM variable directly when diagnosing profile failures.
#[allow(dead_code)]
fn getenv(handle: *mut PamHandle, name: &CStr) -> Option<String> {
    // SAFETY: handle is valid and name is NUL terminated.
    let value = unsafe { pam_getenv(handle, name.as_ptr()) };
    if value.is_null() {
        None
    } else {
        // SAFETY: pam_getenv returned a borrowed NUL-terminated string.
        Some(
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}
