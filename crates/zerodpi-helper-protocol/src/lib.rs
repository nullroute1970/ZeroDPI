//! Versioned, bounded wire protocol for the Android privilege-separated helper.
//!
//! The protocol deliberately contains only data needed by NFQUEUE and the
//! packet handler. It contains no paths, shell fragments, endpoints by name,
//! or general-purpose command fields.

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"ZDHP";
pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 3;
pub const HEADER_LEN: usize = 20;
pub const MAX_FRAME_SIZE: usize = 256 * 1024;
pub const MAX_FAKE_DATA_SIZE: usize = 64 * 1024;
pub const MAX_LIVE_FLOWS: usize = 4096;
pub const SESSION_PROOF_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Hello = 1,
    HelloAccepted = 2,
    ConfigureInterceptor = 3,
    Configured = 4,
    OpenInterceptor = 5,
    InterceptorReady = 6,
    CloseInterceptor = 7,
    InterceptorClosed = 8,
    RegisterFlow = 9,
    FlowRegistered = 10,
    RemoveFlow = 11,
    FlowRemoved = 12,
    FlowProgress = 13,
    Ping = 14,
    Pong = 15,
    Shutdown = 16,
    ShutdownComplete = 17,
    HelperWarning = 18,
    HelperFatal = 19,
    SetLowTtlValue = 20,
    SetLowTtlAck = 21,
}

impl MessageType {
    fn from_u16(value: u16) -> Result<Self, ProtocolError> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::HelloAccepted,
            3 => Self::ConfigureInterceptor,
            4 => Self::Configured,
            5 => Self::OpenInterceptor,
            6 => Self::InterceptorReady,
            7 => Self::CloseInterceptor,
            8 => Self::InterceptorClosed,
            9 => Self::RegisterFlow,
            10 => Self::FlowRegistered,
            11 => Self::RemoveFlow,
            12 => Self::FlowRemoved,
            13 => Self::FlowProgress,
            14 => Self::Ping,
            15 => Self::Pong,
            16 => Self::Shutdown,
            17 => Self::ShutdownComplete,
            18 => Self::HelperWarning,
            19 => Self::HelperFatal,
            20 => Self::SetLowTtlValue,
            21 => Self::SetLowTtlAck,
            other => return Err(ProtocolError::UnknownMessageType(other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub session_proof: Vec<u8>,
    pub data_plane_pid: u32,
    pub build_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAccepted {
    pub peer_uid: u32,
    pub helper_pid: u32,
    pub helper_uid: u32,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptorConfig {
    pub interface_ip: Ipv4Addr,
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: u16,
    pub queue_num: u16,
    pub firewall_backend: FirewallBackend,
    pub method: MethodConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodConfig {
    pub methods: Vec<String>,
    pub wrong_seq_extra_offset: u32,
    pub wrong_seq_set_psh: bool,
    pub wrong_seq_bump_ip_ident: bool,
    pub wrong_checksum_delta: u16,
    pub wrong_checksum_set_psh: bool,
    pub wrong_checksum_bump_ip_ident: bool,
    pub wrong_checksum_complete_immediately: bool,
    pub wrong_md5_set_psh: bool,
    pub wrong_md5_bump_ip_ident: bool,
    pub wrong_md5_complete_immediately: bool,
    pub wrong_ack_offset: u32,
    pub wrong_ack_set_psh: bool,
    pub wrong_ack_bump_ip_ident: bool,
    pub wrong_ack_complete_immediately: bool,
    pub wrong_timestamp_offset: u32,
    pub wrong_timestamp_set_psh: bool,
    pub wrong_timestamp_bump_ip_ident: bool,
    pub wrong_timestamp_complete_immediately: bool,
    pub tls_record_frag_size: usize,
    pub tls_record_frag_set_psh: bool,
    pub tls_record_frag_bump_ip_ident: bool,
    pub low_ttl_value: u8,
    pub low_ttl_set_psh: bool,
    pub low_ttl_bump_ip_ident: bool,
    pub low_ttl_complete_immediately: bool,
}

impl MethodConfig {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        const SUPPORTED: &[&str] = &[
            "wrong_seq",
            "wrong_ack",
            "wrong_checksum",
            "wrong_md5",
            "wrong_timestamp",
            "low_ttl",
            "tls_record_frag",
            "fake_tls",
            "ip_frag",
            "disorder",
            "tls_frag",
            "ccs_prefix",
            "tls_padding",
            "mixed_case_sni",
            "urg_sni_split",
            "sni_boundary_frag",
        ];
        if self.methods.is_empty()
            || self
                .methods
                .iter()
                .any(|m| !SUPPORTED.contains(&m.as_str()))
        {
            return Err(ProtocolError::InvalidField("method names"));
        }
        if self.wrong_checksum_delta == 0 {
            return Err(ProtocolError::InvalidField("wrong checksum delta"));
        }
        if self.wrong_ack_offset == 0 {
            return Err(ProtocolError::InvalidField("wrong ACK offset"));
        }
        if self.wrong_timestamp_offset == 0 {
            return Err(ProtocolError::InvalidField("wrong timestamp offset"));
        }
        if self.low_ttl_value == 0 {
            return Err(ProtocolError::InvalidField("low TTL value"));
        }
        if self.low_ttl_value > 64 {
            return Err(ProtocolError::InvalidField("low TTL value"));
        }
        if self.tls_record_frag_size == 0 || self.tls_record_frag_size > u16::MAX as usize {
            return Err(ProtocolError::InvalidField("TLS record fragment size"));
        }
        Ok(())
    }
}

impl InterceptorConfig {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if invalid_endpoint_address(self.interface_ip) {
            return Err(ProtocolError::InvalidField("interface address"));
        }
        if self.remote_ip.is_some_and(invalid_endpoint_address) {
            return Err(ProtocolError::InvalidField("remote address"));
        }
        if self.remote_port == 0 {
            return Err(ProtocolError::InvalidField("remote port"));
        }
        if self.queue_num == 0 {
            return Err(ProtocolError::InvalidField("queue number"));
        }
        self.method.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if invalid_endpoint_address(self.src_ip) || invalid_endpoint_address(self.dst_ip) {
            return Err(ProtocolError::InvalidField("flow address"));
        }
        if self.src_port == 0 || self.dst_port == 0 {
            return Err(ProtocolError::InvalidField("flow port"));
        }
        Ok(())
    }
}

fn invalid_endpoint_address(address: Ipv4Addr) -> bool {
    address.is_unspecified() || address.is_multicast() || address.is_broadcast()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Progress {
    ReadyForData,
    FakeDataAcked,
    UnexpectedClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthenticationFailed,
    ProtocolMismatch,
    InvalidState,
    InvalidConfig,
    InterceptorFailed,
    FlowLimitReached,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Message {
    Hello(Hello),
    HelloAccepted(HelloAccepted),
    ConfigureInterceptor(InterceptorConfig),
    Configured,
    OpenInterceptor,
    InterceptorReady,
    CloseInterceptor,
    InterceptorClosed,
    RegisterFlow {
        flow_id: u64,
        key: FlowKey,
        fake_data: Vec<u8>,
        /// Per-flow `low_ttl` stamp override carried by `LOW_TTL_DISCOVER`
        /// probe flows. `None` for user flows (they use the live handle).
        /// Additive with a serde default so minor-2 peers remain compatible.
        #[serde(default)]
        low_ttl_override: Option<u8>,
    },
    FlowRegistered {
        flow_id: u64,
    },
    RemoveFlow {
        flow_id: u64,
    },
    FlowRemoved {
        flow_id: u64,
    },
    FlowProgress {
        flow_id: u64,
        progress: Progress,
    },
    Ping,
    Pong,
    Shutdown,
    ShutdownComplete,
    HelperWarning {
        code: ErrorCode,
        message: String,
    },
    HelperFatal {
        code: ErrorCode,
        message: String,
    },
    /// Update the live `low_ttl` method's stamped TTL (used by
    /// `LOW_TTL_DISCOVER`). Only accepted while the interceptor is open.
    SetLowTtlValue {
        value: u8,
    },
    SetLowTtlAck,
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::HelloAccepted(_) => MessageType::HelloAccepted,
            Self::ConfigureInterceptor(_) => MessageType::ConfigureInterceptor,
            Self::Configured => MessageType::Configured,
            Self::OpenInterceptor => MessageType::OpenInterceptor,
            Self::InterceptorReady => MessageType::InterceptorReady,
            Self::CloseInterceptor => MessageType::CloseInterceptor,
            Self::InterceptorClosed => MessageType::InterceptorClosed,
            Self::RegisterFlow { .. } => MessageType::RegisterFlow,
            Self::FlowRegistered { .. } => MessageType::FlowRegistered,
            Self::RemoveFlow { .. } => MessageType::RemoveFlow,
            Self::FlowRemoved { .. } => MessageType::FlowRemoved,
            Self::FlowProgress { .. } => MessageType::FlowProgress,
            Self::Ping => MessageType::Ping,
            Self::Pong => MessageType::Pong,
            Self::Shutdown => MessageType::Shutdown,
            Self::ShutdownComplete => MessageType::ShutdownComplete,
            Self::HelperWarning { .. } => MessageType::HelperWarning,
            Self::HelperFatal { .. } => MessageType::HelperFatal,
            Self::SetLowTtlValue { .. } => MessageType::SetLowTtlValue,
            Self::SetLowTtlAck => MessageType::SetLowTtlAck,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(hello) => {
                if hello.session_proof.len() != SESSION_PROOF_SIZE {
                    return Err(ProtocolError::InvalidField("session proof"));
                }
                if hello.data_plane_pid == 0
                    || hello.build_version.is_empty()
                    || hello.build_version.len() > 64
                {
                    return Err(ProtocolError::InvalidField("hello metadata"));
                }
            }
            Self::ConfigureInterceptor(config) => config.validate()?,
            Self::RegisterFlow {
                flow_id,
                key,
                fake_data,
                low_ttl_override,
            } => {
                if *flow_id == 0 || fake_data.len() > MAX_FAKE_DATA_SIZE {
                    return Err(ProtocolError::InvalidField("flow registration"));
                }
                key.validate()?;
                if low_ttl_override.is_some_and(|v| v == 0 || v > 64) {
                    return Err(ProtocolError::InvalidField("low TTL override"));
                }
            }
            Self::FlowRegistered { flow_id }
            | Self::RemoveFlow { flow_id }
            | Self::FlowRemoved { flow_id }
            | Self::FlowProgress { flow_id, .. }
                if *flow_id == 0 =>
            {
                return Err(ProtocolError::InvalidField("flow id"));
            }
            Self::HelloAccepted(accepted) => {
                if accepted.peer_uid == 0
                    || accepted.helper_pid == 0
                    || accepted.helper_uid != 0
                    || accepted.protocol_major != PROTOCOL_MAJOR
                    || accepted.protocol_minor > PROTOCOL_MINOR
                {
                    return Err(ProtocolError::InvalidField("accepted helper identity"));
                }
                if accepted.capabilities.len() > 32
                    || accepted
                        .capabilities
                        .iter()
                        .any(|capability| capability.is_empty() || capability.len() > 32)
                {
                    return Err(ProtocolError::InvalidField("capabilities"));
                }
            }
            Self::HelperWarning { message, .. } | Self::HelperFatal { message, .. }
                if message.len() > 512 =>
            {
                return Err(ProtocolError::InvalidField("diagnostic message"));
            }
            Self::SetLowTtlValue { value } if *value == 0 || *value > 64 => {
                return Err(ProtocolError::InvalidField("low TTL value"));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub request_id: u32,
    pub flags: u16,
    pub message: Message,
}

impl Frame {
    pub fn new(request_id: u32, message: Message) -> Self {
        Self {
            request_id,
            flags: 0,
            message,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid protocol magic")]
    InvalidMagic,
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("unknown message type {0}")]
    UnknownMessageType(u16),
    #[error("frame payload length {0} exceeds the limit")]
    OversizedFrame(usize),
    #[error("message type in header does not match payload")]
    MessageTypeMismatch,
    #[error("invalid {0}")]
    InvalidField(&'static str),
    #[error("invalid JSON payload: {0}")]
    InvalidPayload(#[from] serde_json::Error),
}

pub fn write_frame(mut writer: impl Write, frame: &Frame) -> Result<(), ProtocolError> {
    if frame.flags != 0 {
        return Err(ProtocolError::InvalidField("frame flags"));
    }
    frame.message.validate()?;
    let payload = serde_json::to_vec(&frame.message)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::OversizedFrame(payload.len()));
    }
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4..6].copy_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
    header[6..8].copy_from_slice(&PROTOCOL_MINOR.to_be_bytes());
    header[8..10].copy_from_slice(&(frame.message.message_type() as u16).to_be_bytes());
    header[10..12].copy_from_slice(&frame.flags.to_be_bytes());
    header[12..16].copy_from_slice(&frame.request_id.to_be_bytes());
    header[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame(mut reader: impl Read) -> Result<Frame, ProtocolError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    if header[0..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let major = u16::from_be_bytes([header[4], header[5]]);
    let minor = u16::from_be_bytes([header[6], header[7]]);
    if major != PROTOCOL_MAJOR || minor > PROTOCOL_MINOR {
        return Err(ProtocolError::UnsupportedVersion { major, minor });
    }
    let message_type = MessageType::from_u16(u16::from_be_bytes([header[8], header[9]]))?;
    let flags = u16::from_be_bytes([header[10], header[11]]);
    if flags != 0 {
        return Err(ProtocolError::InvalidField("frame flags"));
    }
    let request_id = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    let payload_len = u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if payload_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::OversizedFrame(payload_len));
    }
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;
    let message: Message = serde_json::from_slice(&payload)?;
    if message.message_type() != message_type {
        return Err(ProtocolError::MessageTypeMismatch);
    }
    message.validate()?;
    Ok(Frame {
        request_id,
        flags,
        message,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperState {
    Created,
    Authenticated,
    Configured,
    InterceptorOpen,
    ShuttingDown,
    Exited,
}

impl HelperState {
    pub fn accepts(self, message: &Message) -> bool {
        match message {
            Message::Hello(_) => self == Self::Created,
            Message::ConfigureInterceptor(_) => {
                matches!(self, Self::Authenticated | Self::Configured)
            }
            Message::OpenInterceptor => self == Self::Configured,
            Message::RegisterFlow { .. } => self == Self::InterceptorOpen,
            Message::RemoveFlow { .. } => {
                matches!(
                    self,
                    Self::Authenticated | Self::Configured | Self::InterceptorOpen
                )
            }
            Message::CloseInterceptor => matches!(self, Self::Configured | Self::InterceptorOpen),
            Message::SetLowTtlValue { .. } => self == Self::InterceptorOpen,
            Message::Ping => !matches!(self, Self::Created | Self::Exited),
            Message::Shutdown => self != Self::Exited,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Message {
        Message::Hello(Hello {
            session_proof: vec![7; SESSION_PROOF_SIZE],
            data_plane_pid: 42,
            build_version: "test".into(),
        })
    }

    fn method() -> MethodConfig {
        MethodConfig {
            methods: vec!["wrong_seq".into()],
            wrong_seq_extra_offset: 100,
            wrong_seq_set_psh: true,
            wrong_seq_bump_ip_ident: true,
            wrong_checksum_delta: 1,
            wrong_checksum_set_psh: true,
            wrong_checksum_bump_ip_ident: true,
            wrong_checksum_complete_immediately: false,
            wrong_md5_set_psh: true,
            wrong_md5_bump_ip_ident: true,
            wrong_md5_complete_immediately: false,
            wrong_ack_offset: 1,
            wrong_ack_set_psh: true,
            wrong_ack_bump_ip_ident: true,
            wrong_ack_complete_immediately: false,
            wrong_timestamp_offset: 1,
            wrong_timestamp_set_psh: true,
            wrong_timestamp_bump_ip_ident: true,
            wrong_timestamp_complete_immediately: false,
            tls_record_frag_size: 1,
            tls_record_frag_set_psh: true,
            tls_record_frag_bump_ip_ident: true,
            low_ttl_value: 5,
            low_ttl_set_psh: true,
            low_ttl_bump_ip_ident: true,
            low_ttl_complete_immediately: true,
        }
    }

    fn flow_key() -> FlowKey {
        FlowKey {
            src_ip: Ipv4Addr::LOCALHOST,
            src_port: 1000,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        }
    }

    #[test]
    fn round_trip_frame() {
        let frame = Frame::new(9, hello());
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(bytes.as_slice()).unwrap(), frame);
    }

    #[test]
    fn round_trips_every_message_type_and_coalesced_frames() {
        let config = InterceptorConfig {
            interface_ip: Ipv4Addr::new(192, 0, 2, 10),
            remote_ip: Some(Ipv4Addr::new(198, 51, 100, 20)),
            remote_port: 443,
            queue_num: 100,
            firewall_backend: FirewallBackend::Iptables,
            method: method(),
        };
        let messages = vec![
            hello(),
            Message::HelloAccepted(HelloAccepted {
                peer_uid: 10123,
                helper_pid: 7,
                helper_uid: 0,
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
                capabilities: vec!["nfqueue".into()],
            }),
            Message::ConfigureInterceptor(config),
            Message::Configured,
            Message::OpenInterceptor,
            Message::InterceptorReady,
            Message::CloseInterceptor,
            Message::InterceptorClosed,
            Message::RegisterFlow {
                flow_id: 1,
                key: flow_key(),
                fake_data: vec![1, 2, 3],
                low_ttl_override: None,
            },
            Message::FlowRegistered { flow_id: 1 },
            Message::RemoveFlow { flow_id: 1 },
            Message::FlowRemoved { flow_id: 1 },
            Message::FlowProgress {
                flow_id: 1,
                progress: Progress::ReadyForData,
            },
            Message::Ping,
            Message::Pong,
            Message::Shutdown,
            Message::ShutdownComplete,
            Message::HelperWarning {
                code: ErrorCode::Internal,
                message: "warning".into(),
            },
            Message::HelperFatal {
                code: ErrorCode::InterceptorFailed,
                message: "fatal".into(),
            },
            Message::SetLowTtlValue { value: 12 },
            Message::SetLowTtlAck,
        ];

        let mut bytes = Vec::new();
        for (index, message) in messages.iter().cloned().enumerate() {
            write_frame(&mut bytes, &Frame::new(index as u32 + 1, message)).unwrap();
        }
        let mut cursor = std::io::Cursor::new(bytes);
        for (index, expected) in messages.into_iter().enumerate() {
            assert_eq!(
                read_frame(&mut cursor).unwrap(),
                Frame::new(index as u32 + 1, expected)
            );
        }
    }

    #[test]
    fn rejects_truncated_header_and_payload() {
        assert!(matches!(
            read_frame(&[0u8; 4][..]),
            Err(ProtocolError::Io(_))
        ));
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &Frame::new(1, hello())).unwrap();
        bytes.pop();
        assert!(matches!(
            read_frame(bytes.as_slice()),
            Err(ProtocolError::Io(_))
        ));
    }

    #[test]
    fn rejects_oversized_length_before_allocating() {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
        header[6..8].copy_from_slice(&PROTOCOL_MINOR.to_be_bytes());
        header[8..10].copy_from_slice(&(MessageType::Ping as u16).to_be_bytes());
        header[16..20].copy_from_slice(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes());
        assert!(matches!(
            read_frame(header.as_slice()),
            Err(ProtocolError::OversizedFrame(_))
        ));
    }

    #[test]
    fn rejects_unknown_version_type_flags_and_type_mismatch() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &Frame::new(1, Message::Ping)).unwrap();

        let mut wrong_version = bytes.clone();
        wrong_version[4..6].copy_from_slice(&(PROTOCOL_MAJOR + 1).to_be_bytes());
        assert!(matches!(
            read_frame(wrong_version.as_slice()),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let mut unknown_type = bytes.clone();
        unknown_type[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            read_frame(unknown_type.as_slice()),
            Err(ProtocolError::UnknownMessageType(_))
        ));

        let mut flags = bytes.clone();
        flags[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            read_frame(flags.as_slice()),
            Err(ProtocolError::InvalidField("frame flags"))
        ));

        let mut mismatch = bytes;
        mismatch[8..10].copy_from_slice(&(MessageType::Pong as u16).to_be_bytes());
        assert!(matches!(
            read_frame(mismatch.as_slice()),
            Err(ProtocolError::MessageTypeMismatch)
        ));
    }

    #[test]
    fn strict_state_machine_rejects_out_of_order_flow() {
        let flow = Message::RegisterFlow {
            flow_id: 1,
            key: FlowKey {
                src_ip: Ipv4Addr::LOCALHOST,
                src_port: 1000,
                dst_ip: Ipv4Addr::new(1, 1, 1, 1),
                dst_port: 443,
            },
            fake_data: Vec::new(),
            low_ttl_override: None,
        };
        assert!(!HelperState::Configured.accepts(&flow));
        assert!(HelperState::InterceptorOpen.accepts(&flow));
    }

    #[test]
    fn set_low_ttl_value_round_trips_and_validates() {
        let message = Message::SetLowTtlValue { value: 9 };
        let frame = Frame::new(77, message.clone());
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(bytes.as_slice()).unwrap(), frame);
        assert!(message.validate().is_ok());
        assert!(Message::SetLowTtlValue { value: 0 }.validate().is_err());
        assert!(Message::SetLowTtlValue { value: 65 }.validate().is_err());
        assert!(Message::SetLowTtlAck.validate().is_ok());
    }

    #[test]
    fn set_low_ttl_value_requires_open_interceptor() {
        let message = Message::SetLowTtlValue { value: 9 };
        assert!(!HelperState::Configured.accepts(&message));
        assert!(HelperState::InterceptorOpen.accepts(&message));
        assert!(!HelperState::Authenticated.accepts(&message));
    }

    #[test]
    fn rejects_invalid_session_proof_and_flow_payload() {
        let mut invalid = match hello() {
            Message::Hello(value) => value,
            _ => unreachable!(),
        };
        invalid.session_proof.pop();
        assert!(Message::Hello(invalid).validate().is_err());

        let flow = Message::RegisterFlow {
            flow_id: 1,
            key: FlowKey {
                src_ip: Ipv4Addr::LOCALHOST,
                src_port: 1000,
                dst_ip: Ipv4Addr::new(1, 1, 1, 1),
                dst_port: 443,
            },
            fake_data: vec![0; MAX_FAKE_DATA_SIZE + 1],
            low_ttl_override: None,
        };
        assert!(flow.validate().is_err());
    }

    #[test]
    fn rejects_invalid_addresses_ports_queue_and_method_parameters() {
        let mut config = InterceptorConfig {
            interface_ip: Ipv4Addr::UNSPECIFIED,
            remote_ip: None,
            remote_port: 443,
            queue_num: 100,
            firewall_backend: FirewallBackend::Nftables,
            method: method(),
        };
        assert!(config.validate().is_err());
        config.interface_ip = Ipv4Addr::LOCALHOST;
        config.remote_port = 0;
        assert!(config.validate().is_err());
        config.remote_port = 443;
        config.queue_num = 0;
        assert!(config.validate().is_err());
        config.queue_num = 100;
        config.method.methods = vec!["arbitrary_command".into()];
        assert!(config.validate().is_err());

        let mut low_ttl = method();
        low_ttl.methods = vec!["low_ttl".into()];
        low_ttl.low_ttl_value = 0;
        assert!(low_ttl.validate().is_err());
        low_ttl.low_ttl_value = 65;
        assert!(low_ttl.validate().is_err());
        low_ttl.low_ttl_value = 5;
        assert!(low_ttl.validate().is_ok());

        let mut key = flow_key();
        key.dst_ip = Ipv4Addr::BROADCAST;
        assert!(key.validate().is_err());
    }

    #[test]
    fn accepts_every_core_base_bypass_method() {
        // Parity with `zerodpi_core::config::BASE_BYPASS_METHODS` so the wire
        // protocol never rejects a method that the data plane can build.
        // Keep in sync with that constant when new methods are added.
        const CORE_BASE_METHODS: &[&str] = &[
            "wrong_seq",
            "wrong_ack",
            "wrong_checksum",
            "wrong_md5",
            "wrong_timestamp",
            "low_ttl",
            "tls_record_frag",
            "fake_tls",
            "ip_frag",
            "disorder",
            "tls_frag",
            "ccs_prefix",
            "tls_padding",
            "mixed_case_sni",
            "urg_sni_split",
            "sni_boundary_frag",
        ];
        for name in CORE_BASE_METHODS {
            let mut config = method();
            config.methods = vec![(*name).to_owned()];
            assert!(
                config.validate().is_ok(),
                "helper protocol rejects core method {name:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_ccs_prefix_in_mixed_list() {
        let mut config = method();
        config.methods = vec!["wrong_seq".into(), "ccs_prefix".into()];
        config.validate().unwrap();
    }

    #[test]
    fn register_flow_low_ttl_override_round_trips_and_validates() {
        let message = Message::RegisterFlow {
            flow_id: 1,
            key: flow_key(),
            fake_data: vec![1, 2, 3],
            low_ttl_override: Some(9),
        };
        let frame = Frame::new(78, message.clone());
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(bytes.as_slice()).unwrap(), frame);
        assert!(message.validate().is_ok());
        assert!(Message::RegisterFlow {
            flow_id: 1,
            key: flow_key(),
            fake_data: vec![1],
            low_ttl_override: Some(0),
        }
        .validate()
        .is_err());
        assert!(Message::RegisterFlow {
            flow_id: 1,
            key: flow_key(),
            fake_data: vec![1],
            low_ttl_override: Some(65),
        }
        .validate()
        .is_err());
        assert!(Message::RegisterFlow {
            flow_id: 1,
            key: flow_key(),
            fake_data: vec![1],
            low_ttl_override: None,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn register_flow_without_override_field_deserializes_as_none() {
        // Minor-2 app shape: the JSON payload has no `low_ttl_override` key.
        let payload = serde_json::json!({
            "kind": "register_flow",
            "data": {
                "flow_id": 1,
                "key": {
                    "src_ip": "127.0.0.1",
                    "src_port": 1000,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443
                },
                "fake_data": [1, 2, 3]
            }
        });
        let message: Message = serde_json::from_value(payload).unwrap();
        match message {
            Message::RegisterFlow {
                low_ttl_override, ..
            } => assert_eq!(low_ttl_override, None),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn state_machine_allows_reconfiguration_but_rejects_duplicate_open_and_hello() {
        let configure = Message::ConfigureInterceptor(InterceptorConfig {
            interface_ip: Ipv4Addr::LOCALHOST,
            remote_ip: None,
            remote_port: 443,
            queue_num: 100,
            firewall_backend: FirewallBackend::Iptables,
            method: method(),
        });
        assert!(HelperState::Configured.accepts(&configure));
        assert!(!HelperState::InterceptorOpen.accepts(&configure));
        assert!(!HelperState::InterceptorOpen.accepts(&Message::OpenInterceptor));
        assert!(!HelperState::Authenticated.accepts(&hello()));
    }
}
