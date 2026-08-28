//! Bounded wire protocols used by elogind-usersv.
//!
//! Each message is one `SOCK_SEQPACKET` record. Multi-byte integers use big
//! endian byte order. Decoding validates every length before allocating.

use std::fmt;

use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const BACKEND_PROTOCOL_VERSION: &str = "1";
pub const MAGIC: [u8; 4] = *b"EUSV";
pub const HEADER_LEN: usize = 12;
pub const MAX_PACKET_SIZE: usize = 8 * 1024;
pub const MAX_SESSION_ID: usize = 256;
pub const MAX_PATH: usize = 4096;
pub const MAX_MESSAGE: usize = 1024;
pub const MAX_READY_PAYLOAD: usize = 4096;

const PAM_ENSURE_READY: u16 = 1;
const PAM_READY: u16 = 2;
const PAM_ERROR: u16 = 3;

const HELPER_LEASE_OPENED: u16 = 0x100;
const HELPER_LEASE_ACCEPTED: u16 = 0x101;
const HELPER_LEASE_REJECTED: u16 = 0x102;
const HELPER_START: u16 = 0x103;
const HELPER_STOP: u16 = 0x104;
const HELPER_SHUTDOWN: u16 = 0x105;
const HELPER_MANAGER_SPAWNED: u16 = 0x106;
const HELPER_READINESS_PAYLOAD: u16 = 0x107;
const HELPER_READY_SUCCEEDED: u16 = 0x108;
const HELPER_START_FAILED: u16 = 0x109;
const HELPER_MANAGER_EXITED: u16 = 0x10a;
const HELPER_SHUTDOWN_COMPLETE: u16 = 0x10b;
const HELPER_FATAL: u16 = 0x10c;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamRequest {
    EnsureManagerReady {
        session_id: String,
        runtime_dir: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamReply {
    Ready,
    Error { code: ErrorCode, message: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    InvalidRequest = 1,
    PermissionDenied = 2,
    SessionNotFound = 3,
    SessionIneligible = 4,
    Login1Unavailable = 5,
    StartupFailed = 6,
    TimedOut = 7,
    Internal = 8,
    UnsupportedVersion = 9,
}

impl ErrorCode {
    fn from_wire(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::PermissionDenied),
            3 => Ok(Self::SessionNotFound),
            4 => Ok(Self::SessionIneligible),
            5 => Ok(Self::Login1Unavailable),
            6 => Ok(Self::StartupFailed),
            7 => Ok(Self::TimedOut),
            8 => Ok(Self::Internal),
            9 => Ok(Self::UnsupportedVersion),
            _ => Err(ProtocolError::InvalidEnum("error code", value as u32)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonToHelper {
    LeaseAccepted,
    LeaseRejected { reason: String },
    StartManager { attempt: u32 },
    StopManager,
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelperToDaemon {
    LeaseOpened {
        session_id: String,
        runtime_dir: String,
    },
    ManagerSpawned {
        pid: u32,
    },
    ReadinessPayload {
        payload: String,
    },
    ReadySucceeded,
    StartFailed {
        message: String,
    },
    ManagerExited {
        status: ProcessStatus,
    },
    ShutdownComplete,
    Fatal {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStatus {
    Exited(u32),
    Signaled(u32),
    Other(u32),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("packet is shorter than the protocol header")]
    TruncatedHeader,
    #[error("invalid protocol magic")]
    InvalidMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("packet size {0} exceeds the protocol limit")]
    PacketTooLarge(usize),
    #[error("declared payload length does not match packet length")]
    LengthMismatch,
    #[error("unknown message kind {0:#x}")]
    UnknownKind(u16),
    #[error("field {field} has invalid length {actual} (allowed {min}..={max})")]
    InvalidFieldLength {
        field: &'static str,
        actual: usize,
        min: usize,
        max: usize,
    },
    #[error("field {0} is not valid UTF-8")]
    InvalidUtf8(&'static str),
    #[error("field {0} contains a NUL byte")]
    InteriorNul(&'static str),
    #[error("invalid {0} value {1}")]
    InvalidEnum(&'static str, u32),
    #[error("message has trailing data")]
    TrailingData,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReadinessError {
    #[error("readiness FIFO reached EOF before NUL")]
    EofBeforeTerminator,
    #[error("readiness payload is empty")]
    Empty,
    #[error("readiness payload exceeds {MAX_READY_PAYLOAD} bytes")]
    Oversized,
    #[error("readiness payload is not valid UTF-8")]
    InvalidUtf8,
    #[error("multiple or trailing readiness messages received")]
    MultipleMessages,
    #[error("readiness frame was already completed")]
    AlreadyComplete,
}

#[derive(Debug, Default)]
pub struct ReadinessFrame {
    bytes: Vec<u8>,
    complete: bool,
}

impl ReadinessFrame {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<String>, ReadinessError> {
        if self.complete {
            return Err(ReadinessError::AlreadyComplete);
        }
        self.bytes.extend_from_slice(chunk);
        if let Some(terminator) = self.bytes.iter().position(|byte| *byte == 0) {
            if terminator == 0 {
                return Err(ReadinessError::Empty);
            }
            if terminator != self.bytes.len() - 1 {
                return Err(ReadinessError::MultipleMessages);
            }
            if terminator > MAX_READY_PAYLOAD {
                return Err(ReadinessError::Oversized);
            }
            let payload = std::str::from_utf8(&self.bytes[..terminator])
                .map_err(|_| ReadinessError::InvalidUtf8)?
                .to_owned();
            self.complete = true;
            return Ok(Some(payload));
        }
        if self.bytes.len() > MAX_READY_PAYLOAD {
            return Err(ReadinessError::Oversized);
        }
        Ok(None)
    }

    pub fn eof(&self) -> Result<(), ReadinessError> {
        if self.complete {
            Ok(())
        } else {
            Err(ReadinessError::EofBeforeTerminator)
        }
    }
}

pub trait WireMessage: Sized {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError>;
    fn decode(packet: &[u8]) -> Result<Self, ProtocolError>;
}

impl WireMessage for PamRequest {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::EnsureManagerReady {
                session_id,
                runtime_dir,
            } => encode_message(PAM_ENSURE_READY, |out| {
                out.string("session ID", session_id, 1, MAX_SESSION_ID)?;
                out.string("runtime directory", runtime_dir, 1, MAX_PATH)
            }),
        }
    }

    fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        let (kind, mut input) = decode_header(packet)?;
        let value = match kind {
            PAM_ENSURE_READY => Self::EnsureManagerReady {
                session_id: input.string("session ID", 1, MAX_SESSION_ID)?,
                runtime_dir: input.string("runtime directory", 1, MAX_PATH)?,
            },
            _ => return Err(ProtocolError::UnknownKind(kind)),
        };
        input.finish()?;
        Ok(value)
    }
}

impl WireMessage for PamReply {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Ready => encode_message(PAM_READY, |_| Ok(())),
            Self::Error { code, message } => encode_message(PAM_ERROR, |out| {
                out.u16(*code as u16);
                out.string("error message", message, 1, MAX_MESSAGE)
            }),
        }
    }

    fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        let (kind, mut input) = decode_header(packet)?;
        let value = match kind {
            PAM_READY => Self::Ready,
            PAM_ERROR => Self::Error {
                code: ErrorCode::from_wire(input.u16()?)?,
                message: input.string("error message", 1, MAX_MESSAGE)?,
            },
            _ => return Err(ProtocolError::UnknownKind(kind)),
        };
        input.finish()?;
        Ok(value)
    }
}

impl WireMessage for DaemonToHelper {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::LeaseAccepted => encode_message(HELPER_LEASE_ACCEPTED, |_| Ok(())),
            Self::LeaseRejected { reason } => encode_message(HELPER_LEASE_REJECTED, |out| {
                out.string("lease rejection reason", reason, 1, MAX_MESSAGE)
            }),
            Self::StartManager { attempt } => encode_message(HELPER_START, |out| {
                out.u32(*attempt);
                Ok(())
            }),
            Self::StopManager => encode_message(HELPER_STOP, |_| Ok(())),
            Self::Shutdown => encode_message(HELPER_SHUTDOWN, |_| Ok(())),
        }
    }

    fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        let (kind, mut input) = decode_header(packet)?;
        let value = match kind {
            HELPER_LEASE_ACCEPTED => Self::LeaseAccepted,
            HELPER_LEASE_REJECTED => Self::LeaseRejected {
                reason: input.string("lease rejection reason", 1, MAX_MESSAGE)?,
            },
            HELPER_START => Self::StartManager {
                attempt: input.u32()?,
            },
            HELPER_STOP => Self::StopManager,
            HELPER_SHUTDOWN => Self::Shutdown,
            _ => return Err(ProtocolError::UnknownKind(kind)),
        };
        input.finish()?;
        Ok(value)
    }
}

impl WireMessage for HelperToDaemon {
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::LeaseOpened {
                session_id,
                runtime_dir,
            } => encode_message(HELPER_LEASE_OPENED, |out| {
                out.string("session ID", session_id, 1, MAX_SESSION_ID)?;
                out.string("runtime directory", runtime_dir, 1, MAX_PATH)
            }),
            Self::ManagerSpawned { pid } => encode_message(HELPER_MANAGER_SPAWNED, |out| {
                out.u32(*pid);
                Ok(())
            }),
            Self::ReadinessPayload { payload } => encode_message(HELPER_READINESS_PAYLOAD, |out| {
                out.string("readiness payload", payload, 1, MAX_READY_PAYLOAD)
            }),
            Self::ReadySucceeded => encode_message(HELPER_READY_SUCCEEDED, |_| Ok(())),
            Self::StartFailed { message } => encode_message(HELPER_START_FAILED, |out| {
                out.string("startup failure", message, 1, MAX_MESSAGE)
            }),
            Self::ManagerExited { status } => encode_message(HELPER_MANAGER_EXITED, |out| {
                let (kind, value) = match status {
                    ProcessStatus::Exited(value) => (1, *value),
                    ProcessStatus::Signaled(value) => (2, *value),
                    ProcessStatus::Other(value) => (3, *value),
                };
                out.u16(kind);
                out.u32(value);
                Ok(())
            }),
            Self::ShutdownComplete => encode_message(HELPER_SHUTDOWN_COMPLETE, |_| Ok(())),
            Self::Fatal { message } => encode_message(HELPER_FATAL, |out| {
                out.string("fatal error", message, 1, MAX_MESSAGE)
            }),
        }
    }

    fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        let (kind, mut input) = decode_header(packet)?;
        let value = match kind {
            HELPER_LEASE_OPENED => Self::LeaseOpened {
                session_id: input.string("session ID", 1, MAX_SESSION_ID)?,
                runtime_dir: input.string("runtime directory", 1, MAX_PATH)?,
            },
            HELPER_MANAGER_SPAWNED => Self::ManagerSpawned { pid: input.u32()? },
            HELPER_READINESS_PAYLOAD => Self::ReadinessPayload {
                payload: input.string("readiness payload", 1, MAX_READY_PAYLOAD)?,
            },
            HELPER_READY_SUCCEEDED => Self::ReadySucceeded,
            HELPER_START_FAILED => Self::StartFailed {
                message: input.string("startup failure", 1, MAX_MESSAGE)?,
            },
            HELPER_MANAGER_EXITED => {
                let kind = input.u16()?;
                let value = input.u32()?;
                Self::ManagerExited {
                    status: match kind {
                        1 => ProcessStatus::Exited(value),
                        2 => ProcessStatus::Signaled(value),
                        3 => ProcessStatus::Other(value),
                        _ => return Err(ProtocolError::InvalidEnum("process status", kind as u32)),
                    },
                }
            }
            HELPER_SHUTDOWN_COMPLETE => Self::ShutdownComplete,
            HELPER_FATAL => Self::Fatal {
                message: input.string("fatal error", 1, MAX_MESSAGE)?,
            },
            _ => return Err(ProtocolError::UnknownKind(kind)),
        };
        input.finish()?;
        Ok(value)
    }
}

fn encode_message(
    kind: u16,
    encode_payload: impl FnOnce(&mut Encoder) -> Result<(), ProtocolError>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Encoder::default();
    encode_payload(&mut payload)?;
    let total = HEADER_LEN + payload.0.len();
    if total > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLarge(total));
    }

    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&MAGIC);
    packet.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&(payload.0.len() as u32).to_be_bytes());
    packet.extend_from_slice(&payload.0);
    Ok(packet)
}

fn decode_header(packet: &[u8]) -> Result<(u16, Decoder<'_>), ProtocolError> {
    if packet.len() > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLarge(packet.len()));
    }
    if packet.len() < HEADER_LEN {
        return Err(ProtocolError::TruncatedHeader);
    }
    if packet[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = u16::from_be_bytes([packet[4], packet[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = u16::from_be_bytes([packet[6], packet[7]]);
    let payload_len = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]) as usize;
    if payload_len != packet.len() - HEADER_LEN {
        return Err(ProtocolError::LengthMismatch);
    }
    Ok((kind, Decoder(&packet[HEADER_LEN..])))
}

#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn string(
        &mut self,
        field: &'static str,
        value: &str,
        min: usize,
        max: usize,
    ) -> Result<(), ProtocolError> {
        validate_string(field, value, min, max)?;
        self.u16(value.len() as u16);
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

struct Decoder<'a>(&'a [u8]);

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
        if count > self.0.len() {
            return Err(ProtocolError::LengthMismatch);
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
    ) -> Result<String, ProtocolError> {
        let len = self.u16()? as usize;
        if !(min..=max).contains(&len) {
            return Err(ProtocolError::InvalidFieldLength {
                field,
                actual: len,
                min,
                max,
            });
        }
        let bytes = self.take(len)?;
        let value = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8(field))?;
        if value.as_bytes().contains(&0) {
            return Err(ProtocolError::InteriorNul(field));
        }
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingData)
        }
    }
}

fn validate_string(
    field: &'static str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), ProtocolError> {
    let actual = value.len();
    if !(min..=max).contains(&actual) {
        return Err(ProtocolError::InvalidFieldLength {
            field,
            actual,
            min,
            max,
        });
    }
    if value.as_bytes().contains(&0) {
        return Err(ProtocolError::InteriorNul(field));
    }
    Ok(())
}

impl fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exit code {code}"),
            Self::Signaled(signal) => write!(f, "signal {signal}"),
            Self::Other(raw) => write!(f, "raw status {raw}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(message: T)
    where
        T: WireMessage + Eq + fmt::Debug,
    {
        let encoded = message.encode().unwrap();
        assert_eq!(T::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn pam_messages_round_trip() {
        round_trip(PamRequest::EnsureManagerReady {
            session_id: "c3".into(),
            runtime_dir: "/run/user/1000".into(),
        });
        round_trip(PamReply::Ready);
        round_trip(PamReply::Error {
            code: ErrorCode::StartupFailed,
            message: "backend failed".into(),
        });
    }

    #[test]
    fn helper_messages_round_trip() {
        let daemon_messages = [
            DaemonToHelper::LeaseAccepted,
            DaemonToHelper::LeaseRejected {
                reason: "wrong class".into(),
            },
            DaemonToHelper::StartManager { attempt: 7 },
            DaemonToHelper::StopManager,
            DaemonToHelper::Shutdown,
        ];
        for message in daemon_messages {
            round_trip(message);
        }

        let helper_messages = [
            HelperToDaemon::LeaseOpened {
                session_id: "c9".into(),
                runtime_dir: "/run/user/1000".into(),
            },
            HelperToDaemon::ManagerSpawned { pid: 1234 },
            HelperToDaemon::ReadinessPayload {
                payload: "svscan-ready".into(),
            },
            HelperToDaemon::ReadySucceeded,
            HelperToDaemon::StartFailed {
                message: "EOF before NUL".into(),
            },
            HelperToDaemon::ManagerExited {
                status: ProcessStatus::Signaled(9),
            },
            HelperToDaemon::ShutdownComplete,
            HelperToDaemon::Fatal {
                message: "PAM failed".into(),
            },
        ];
        for message in helper_messages {
            round_trip(message);
        }
    }

    #[test]
    fn rejects_malformed_headers() {
        assert_eq!(PamReply::decode(&[]), Err(ProtocolError::TruncatedHeader));

        let mut packet = PamReply::Ready.encode().unwrap();
        packet[0] = b'X';
        assert_eq!(PamReply::decode(&packet), Err(ProtocolError::InvalidMagic));

        let mut packet = PamReply::Ready.encode().unwrap();
        packet[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            PamReply::decode(&packet),
            Err(ProtocolError::UnsupportedVersion(2))
        );

        let mut packet = PamReply::Ready.encode().unwrap();
        packet[8..12].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            PamReply::decode(&packet),
            Err(ProtocolError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_truncation_and_trailing_data() {
        let message = PamRequest::EnsureManagerReady {
            session_id: "c3".into(),
            runtime_dir: "/run/user/1000".into(),
        };
        let mut packet = message.encode().unwrap();
        packet.pop();
        let payload_len = (packet.len() - HEADER_LEN) as u32;
        packet[8..12].copy_from_slice(&payload_len.to_be_bytes());
        assert_eq!(
            PamRequest::decode(&packet),
            Err(ProtocolError::LengthMismatch)
        );

        let mut packet = PamReply::Ready.encode().unwrap();
        packet.push(0);
        let payload_len = (packet.len() - HEADER_LEN) as u32;
        packet[8..12].copy_from_slice(&payload_len.to_be_bytes());
        assert_eq!(PamReply::decode(&packet), Err(ProtocolError::TrailingData));
    }

    #[test]
    fn rejects_empty_oversized_nul_and_invalid_utf8_strings() {
        let empty = PamRequest::EnsureManagerReady {
            session_id: String::new(),
            runtime_dir: "/run/user/1000".into(),
        };
        assert!(matches!(
            empty.encode(),
            Err(ProtocolError::InvalidFieldLength { .. })
        ));

        let oversized = HelperToDaemon::ReadinessPayload {
            payload: "x".repeat(MAX_READY_PAYLOAD + 1),
        };
        assert!(matches!(
            oversized.encode(),
            Err(ProtocolError::InvalidFieldLength { .. })
        ));

        let nul = PamRequest::EnsureManagerReady {
            session_id: "c\0evil".into(),
            runtime_dir: "/run/user/1000".into(),
        };
        assert_eq!(nul.encode(), Err(ProtocolError::InteriorNul("session ID")));

        let mut packet = PamRequest::EnsureManagerReady {
            session_id: "c3".into(),
            runtime_dir: "/run/user/1000".into(),
        }
        .encode()
        .unwrap();
        packet[HEADER_LEN + 2] = 0xff;
        assert_eq!(
            PamRequest::decode(&packet),
            Err(ProtocolError::InvalidUtf8("session ID"))
        );
    }

    #[test]
    fn readiness_framing_is_incremental_and_strict() {
        let mut frame = ReadinessFrame::default();
        assert_eq!(frame.push(b"svscan-").unwrap(), None);
        assert_eq!(frame.push(b"ready\0").unwrap(), Some("svscan-ready".into()));
        assert_eq!(frame.push(b"again\0"), Err(ReadinessError::AlreadyComplete));

        let mut frame = ReadinessFrame::default();
        assert_eq!(frame.push(b"\0"), Err(ReadinessError::Empty));
        let mut frame = ReadinessFrame::default();
        assert_eq!(
            frame.push(b"one\0two\0"),
            Err(ReadinessError::MultipleMessages)
        );
        let mut frame = ReadinessFrame::default();
        assert_eq!(frame.push(&[0xff, 0]), Err(ReadinessError::InvalidUtf8));
        let mut frame = ReadinessFrame::default();
        assert_eq!(
            frame.push(&vec![b'x'; MAX_READY_PAYLOAD + 1]),
            Err(ReadinessError::Oversized)
        );
        let mut frame = ReadinessFrame::default();
        frame.push(b"incomplete").unwrap();
        assert_eq!(frame.eof(), Err(ReadinessError::EofBeforeTerminator));
    }

    #[test]
    fn rejects_unknown_kinds_and_error_codes() {
        let mut packet = PamReply::Ready.encode().unwrap();
        packet[6..8].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert_eq!(
            PamReply::decode(&packet),
            Err(ProtocolError::UnknownKind(0xffff))
        );

        let mut packet = PamReply::Error {
            code: ErrorCode::Internal,
            message: "error".into(),
        }
        .encode()
        .unwrap();
        packet[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert_eq!(
            PamReply::decode(&packet),
            Err(ProtocolError::InvalidEnum("error code", 0xffff))
        );
    }
}
