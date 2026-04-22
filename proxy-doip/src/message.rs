/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use bytes::{BufMut, BytesMut};

/// `DoIP` protocol version per ISO 13400-2.
pub const DOIP_PROTOCOL_VERSION: u8 = 0x02;

/// `DoIP` header size in bytes: version (1) + inverse (1) + type (2) + length (4).
pub const DOIP_HEADER_SIZE: usize = 8;

/// Minimum routing activation request payload: source address (2) + type (1) + reserved (4).
const ROUTING_ACTIVATION_REQUEST_MIN_LEN: usize = 7;

/// Diagnostic message header size: source address (2) + target address (2).
pub const DIAGNOSTIC_MESSAGE_HEADER_SIZE: usize = 4;

/// `DoIP` payload types defined in ISO 13400-2.
///
/// Each variant carries the 16-bit payload type code used on the wire.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Generic `DoIP` header negative acknowledge
    GenericHeaderNack = 0x0000,
    /// Vehicle identification request
    VehicleIdentificationRequest = 0x0001,
    /// Vehicle identification request with EID
    VehicleIdentificationRequestWithEid = 0x0002,
    /// Vehicle identification request with VIN
    VehicleIdentificationRequestWithVin = 0x0003,
    /// Vehicle announcement/identification response
    VehicleAnnouncementIdentificationResponse = 0x0004,
    /// Routing activation request
    RoutingActivationRequest = 0x0005,
    /// Routing activation response
    RoutingActivationResponse = 0x0006,
    /// Alive check request
    AliveCheckRequest = 0x0007,
    /// Alive check response
    AliveCheckResponse = 0x0008,
    /// Diagnostic message
    DiagnosticMessage = 0x8001,
    /// Diagnostic message positive acknowledgement
    DiagnosticMessagePositiveAck = 0x8002,
    /// Diagnostic message negative acknowledgement
    DiagnosticMessageNegativeAck = 0x8003,
}

impl PayloadType {
    /// Convert a raw `u16` wire value to a [`PayloadType`].
    ///
    /// Returns `None` for unknown payload type codes.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::GenericHeaderNack),
            0x0001 => Some(Self::VehicleIdentificationRequest),
            0x0002 => Some(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Some(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Some(Self::VehicleAnnouncementIdentificationResponse),
            0x0005 => Some(Self::RoutingActivationRequest),
            0x0006 => Some(Self::RoutingActivationResponse),
            0x0007 => Some(Self::AliveCheckRequest),
            0x0008 => Some(Self::AliveCheckResponse),
            0x8001 => Some(Self::DiagnosticMessage),
            0x8002 => Some(Self::DiagnosticMessagePositiveAck),
            0x8003 => Some(Self::DiagnosticMessageNegativeAck),
            _ => None,
        }
    }
}

/// `DoIP` message consisting of a header and variable-length payload.
///
/// The header contains the protocol version, inverse version byte,
/// 16-bit payload type, and 32-bit payload length per ISO 13400-2.
#[derive(Debug, Clone)]
pub struct DoIpMessage {
    /// Protocol version byte (typically [`DOIP_PROTOCOL_VERSION`]).
    pub protocol_version: u8,
    /// Raw 16-bit payload type code.
    pub payload_type: u16,
    /// Variable-length payload bytes.
    pub payload: Vec<u8>,
}

impl DoIpMessage {
    /// Create a new `DoIP` message with the given payload type and data.
    #[must_use]
    pub fn new(payload_type: PayloadType, payload: Vec<u8>) -> Self {
        Self {
            protocol_version: DOIP_PROTOCOL_VERSION,
            payload_type: payload_type as u16,
            payload,
        }
    }

    /// Parse a `DoIP` message from a byte buffer.
    ///
    /// Returns `None` if the buffer is too short, the protocol version is invalid,
    /// or the declared payload length exceeds the available data.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < DOIP_HEADER_SIZE {
            return None;
        }

        let protocol_version = *data.first()?;
        let inverse_protocol_version = *data.get(1)?;

        // Verify protocol version per ISO 13400-2
        if protocol_version != DOIP_PROTOCOL_VERSION {
            return None;
        }
        if inverse_protocol_version != !protocol_version {
            return None;
        }

        let pt_bytes: [u8; 2] = data.get(2..4)?.try_into().ok()?;
        let payload_type = u16::from_be_bytes(pt_bytes);

        let pl_bytes: [u8; 4] = data.get(4..8)?.try_into().ok()?;
        let payload_length = u32::from_be_bytes(pl_bytes) as usize;

        let end = DOIP_HEADER_SIZE.checked_add(payload_length)?;
        let payload = data.get(DOIP_HEADER_SIZE..end)?.to_vec();

        Some(Self {
            protocol_version,
            payload_type,
            payload,
        })
    }

    /// Serialize this message to wire-format bytes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(DOIP_HEADER_SIZE.saturating_add(self.payload.len()));

        buf.put_u8(self.protocol_version);
        buf.put_u8(!self.protocol_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);

        buf.to_vec()
    }

    /// Get the typed [`PayloadType`] enum for this message.
    #[must_use]
    pub fn payload_type_enum(&self) -> Option<PayloadType> {
        PayloadType::from_u16(self.payload_type)
    }
}

/// Parsed routing activation request (ISO 13400-2 Table 18).
#[derive(Debug)]
pub struct RoutingActivationRequest {
    /// Source address of the external test equipment.
    pub source_address: u16,
    /// Routing activation type (default / diagnostic / central security).
    pub activation_type: u8,
    /// Reserved bytes specified by ISO (OEM-specific use).
    /// TODO(doip): Use for OEM-specific routing activation handling.
    #[allow(dead_code)]
    pub reserved: u32,
}

impl RoutingActivationRequest {
    /// Parse a routing activation request from a `DoIP` payload.
    ///
    /// Returns `None` if the payload is shorter than the minimum 7 bytes.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < ROUTING_ACTIVATION_REQUEST_MIN_LEN {
            return None;
        }

        let sa: [u8; 2] = payload.get(0..2)?.try_into().ok()?;
        let source_address = u16::from_be_bytes(sa);
        let activation_type = *payload.get(2)?;
        let res: [u8; 4] = payload.get(3..7)?.try_into().ok()?;
        let reserved = u32::from_be_bytes(res);

        Some(Self {
            source_address,
            activation_type,
            reserved,
        })
    }
}

/// Parsed diagnostic message (ISO 13400-2 Table 21).
#[derive(Debug)]
pub struct DiagnosticMessage {
    /// Source address of the sending entity.
    pub source_address: u16,
    /// Target address of the receiving entity.
    pub target_address: u16,
    /// UDS user data (service bytes).
    pub user_data: Vec<u8>,
}

impl DiagnosticMessage {
    /// Parse a diagnostic message from a `DoIP` payload.
    ///
    /// Returns `None` if the payload is shorter than the minimum 4 bytes.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < DIAGNOSTIC_MESSAGE_HEADER_SIZE {
            return None;
        }

        let sa: [u8; 2] = payload.get(0..2)?.try_into().ok()?;
        let source_address = u16::from_be_bytes(sa);
        let ta: [u8; 2] = payload.get(2..4)?.try_into().ok()?;
        let target_address = u16::from_be_bytes(ta);
        let user_data = payload.get(4..).unwrap_or_default().to_vec();

        Some(Self {
            source_address,
            target_address,
            user_data,
        })
    }

    /// Build a raw diagnostic message payload from addresses and UDS data.
    #[must_use]
    pub fn build_payload(source_address: u16, target_address: u16, user_data: &[u8]) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(DIAGNOSTIC_MESSAGE_HEADER_SIZE.saturating_add(user_data.len()));
        payload.extend_from_slice(&source_address.to_be_bytes());
        payload.extend_from_slice(&target_address.to_be_bytes());
        payload.extend_from_slice(user_data);
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doip_message_serialize() {
        let msg = DoIpMessage::new(PayloadType::DiagnosticMessage, vec![0x01, 0x02, 0x03]);
        let bytes = msg.to_bytes();

        let (&b0, &b1) = (bytes.first().expect("b0"), bytes.get(1).expect("b1"));
        let pt: [u8; 2] = bytes.get(2..4).expect("pt").try_into().expect("2b");
        let len_field: [u8; 4] = bytes.get(4..8).expect("len").try_into().expect("4b");
        let rest = bytes.get(8..).expect("rest");
        assert_eq!(b0, DOIP_PROTOCOL_VERSION);
        assert_eq!(b1, !DOIP_PROTOCOL_VERSION);
        assert_eq!(u16::from_be_bytes(pt), 0x8001);
        assert_eq!(u32::from_be_bytes(len_field), 3);
        assert_eq!(rest, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_doip_message_deserialize() {
        let bytes = vec![
            0x02, 0xFD, // Version and inverse
            0x80, 0x01, // Payload type (DiagnosticMessage)
            0x00, 0x00, 0x00, 0x03, // Payload length
            0x01, 0x02, 0x03, // Payload
        ];

        let msg = DoIpMessage::from_bytes(&bytes).expect("failed to parse valid DoIP message");
        assert_eq!(msg.protocol_version, 0x02);
        assert_eq!(msg.payload_type, 0x8001);
        assert_eq!(msg.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_diagnostic_message_parser() {
        let payload = vec![
            0x0E, 0x80, // Source address
            0x00, 0x01, // Target address
            0x22, 0xF1, 0x90, // UDS data
        ];

        let diag_msg = DiagnosticMessage::from_payload(&payload)
            .expect("failed to parse valid diagnostic message");
        assert_eq!(diag_msg.source_address, 0x0E80);
        assert_eq!(diag_msg.target_address, 0x0001);
        assert_eq!(diag_msg.user_data, vec![0x22, 0xF1, 0x90]);
    }

    #[test]
    fn test_routing_activation_request() {
        let payload = vec![
            0x0E, 0x80, // Source address
            0x00, // Activation type
            0x00, 0x00, 0x00, 0x00, // Reserved
        ];

        let req = RoutingActivationRequest::from_payload(&payload)
            .expect("failed to parse valid routing activation request");
        assert_eq!(req.source_address, 0x0E80);
        assert_eq!(req.activation_type, 0x00);
    }

    #[test]
    fn test_doip_message_roundtrip() {
        let original = DoIpMessage::new(
            PayloadType::RoutingActivationRequest,
            vec![0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        let bytes = original.to_bytes();
        let parsed =
            DoIpMessage::from_bytes(&bytes).expect("failed to parse roundtrip DoIP message");
        assert_eq!(parsed.protocol_version, original.protocol_version);
        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_doip_message_too_short() {
        assert!(DoIpMessage::from_bytes(&[0x02, 0xFD]).is_none());
        assert!(DoIpMessage::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_doip_message_invalid_version() {
        let bytes = vec![0x03, 0xFC, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(DoIpMessage::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_doip_message_incomplete_payload() {
        let bytes = vec![
            0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x05, // Says 5 bytes but only 2 follow
            0x01, 0x02,
        ];
        assert!(DoIpMessage::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_payload_type_from_u16() {
        assert_eq!(
            PayloadType::from_u16(0x0005),
            Some(PayloadType::RoutingActivationRequest)
        );
        assert_eq!(
            PayloadType::from_u16(0x8001),
            Some(PayloadType::DiagnosticMessage)
        );
        assert_eq!(PayloadType::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_diagnostic_message_build_payload() {
        let payload = DiagnosticMessage::build_payload(0x0E80, 0x1000, &[0x22, 0xF1, 0x90]);
        assert_eq!(payload, vec![0x0E, 0x80, 0x10, 0x00, 0x22, 0xF1, 0x90]);
    }

    #[test]
    fn test_diagnostic_message_too_short() {
        assert!(DiagnosticMessage::from_payload(&[0x0E, 0x80]).is_none());
    }

    #[test]
    fn test_routing_activation_too_short() {
        assert!(RoutingActivationRequest::from_payload(&[0x0E, 0x80]).is_none());
    }
}
