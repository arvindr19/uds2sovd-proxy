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

use std::sync::Arc;

use cda_interfaces::service_ids;
use proxy_core::{
    Config, DiagHandler, Result,
    error::{Nrc, UdsError},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, info, warn};

use crate::{
    message::{
        DOIP_HEADER_SIZE, DOIP_PROTOCOL_VERSION, DiagnosticMessage, DoIpMessage, PayloadType,
        RoutingActivationRequest,
    },
    session::Session,
};

/// ISO 13400 routing activation response code: success.
const ROUTING_ACTIVATION_SUCCESS: u8 = 0x10;

/// Socket read chunk size used for each `read` call.
const READ_BUFFER_SIZE: usize = 4096;

/// Maximum buffered bytes retained while waiting for complete `DoIP` frames.
const MAX_STAGED_BUFFER_BYTES: usize = 65_536;

/// Maximum parsed frames per read cycle to keep scheduling fair.
const MAX_FRAMES_PER_READ: usize = 128;

/// Read service minimum length: SID (1 byte) + DID (2 bytes) = 3 bytes.
const MIN_READ_SERVICE_LENGTH: usize = 3;

/// Minimum data bytes for a `WriteDataByIdentifier` request (DID hi + DID lo + 1 data byte).
const MIN_WDBI_DATA_LENGTH: usize = 3;

/// Minimum data bytes for a `ReadDataByIdentifier` request: DID high byte + DID low byte.
const MIN_RDBI_DATA_LENGTH: usize = 2;

/// Placeholder service ID used in a negative response when UDS message parsing fails.
const UNKNOWN_SERVICE_ID: u8 = 0x00;

/// Parsed UDS message consisting of a service identifier and data bytes.
#[derive(Debug, Clone)]
struct UdsMessage {
    /// UDS Service Identifier (SID), e.g. 0x22 for `ReadDataByIdentifier`.
    service_id: u8,
    /// Remaining bytes after the SID (sub-function, DID, data, etc.).
    data: Vec<u8>,
}

impl UdsMessage {
    /// Parse a UDS message from raw bytes.
    ///
    /// The first byte is interpreted as the SID; the rest becomes `data`.
    ///
    /// # Errors
    /// Returns an error if the byte slice is empty.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let &first = bytes.first().ok_or(UdsError::InvalidLength {
            expected: 1,
            actual: 0,
        })?;

        Ok(Self {
            service_id: first,
            data: bytes.get(1..).unwrap_or_default().to_vec(),
        })
    }

    /// Build a UDS negative response: `[0x7F, SID, NRC]`.
    #[must_use]
    fn build_negative_response(&self, nrc: Nrc) -> Vec<u8> {
        vec![service_ids::NEGATIVE_RESPONSE, self.service_id, nrc as u8]
    }

    /// Extract a 16-bit DID from the first two data bytes.
    fn extract_did(&self) -> Option<u16> {
        let &hi = self.data.first()?;
        let &lo = self.data.get(1)?;
        Some(u16::from_be_bytes([hi, lo]))
    }
}

/// Returns `true` when a full header is present but protocol bytes are invalid.
fn has_invalid_doip_header(buffer: &[u8]) -> bool {
    if buffer.len() < DOIP_HEADER_SIZE {
        return false;
    }

    let Some(&version) = buffer.first() else {
        return false;
    };
    let Some(&inverse) = buffer.get(1) else {
        return false;
    };

    version != DOIP_PROTOCOL_VERSION || inverse != !version
}

/// Handles a single `DoIP` TCP connection.
///
/// Reads incoming `DoIP` frames, dispatches UDS requests to the
/// [`DiagHandler`] backend, and sends the encoded response back.
pub struct ConnectionHandler {
    /// Shared proxy configuration.
    config: Arc<Config>,
    /// Backend handler for UDS request processing.
    diag_handler: Arc<dyn DiagHandler>,
    /// Active TCP stream for this connection.
    stream: TcpStream,
    /// Routing activation session state.
    session: Session,
    /// Accumulation buffer for partial `DoIP` frames.
    buffer: Vec<u8>,
}

impl ConnectionHandler {
    /// Create a new connection handler.
    pub fn new(config: Arc<Config>, diag_handler: Arc<dyn DiagHandler>, stream: TcpStream) -> Self {
        Self {
            config,
            diag_handler,
            stream,
            session: Session::new(),
            buffer: Vec::with_capacity(READ_BUFFER_SIZE),
        }
    }

    /// Run the connection handler loop until the client disconnects or an error occurs.
    ///
    /// # Errors
    /// Returns an error if the connection encounters an I/O error.
    pub async fn handle(mut self) -> Result<()> {
        let peer_addr = self.stream.peer_addr()?;
        info!("New connection from {}", peer_addr);

        let mut read_buf = vec![0u8; READ_BUFFER_SIZE];

        loop {
            match self.stream.read(&mut read_buf).await {
                Ok(0) => {
                    info!("Client {} disconnected", peer_addr);
                    break;
                }
                Ok(n) => {
                    debug!("Received {} bytes from {}", n, peer_addr);
                    self.buffer
                        .extend_from_slice(read_buf.get(..n).unwrap_or_default());

                    let mut parsed_frames = 0usize;
                    while parsed_frames < MAX_FRAMES_PER_READ {
                        if let Some(msg) = DoIpMessage::from_bytes(&self.buffer) {
                            let msg_size = DOIP_HEADER_SIZE.saturating_add(msg.payload.len());
                            if msg_size > self.buffer.len() {
                                warn!(
                                    "Parsed message length {} exceeds buffered bytes {}, clearing",
                                    msg_size,
                                    self.buffer.len(),
                                );
                                self.buffer.clear();
                                break;
                            }

                            if let Err(e) = self.process_message(&msg).await {
                                error!("Error processing message from {}: {}", peer_addr, e);
                                return Err(e);
                            }

                            self.buffer.drain(..msg_size);
                            parsed_frames = parsed_frames.saturating_add(1);
                            continue;
                        }

                        if has_invalid_doip_header(&self.buffer) {
                            warn!(
                                "Invalid DoIP header from {}, discarding one byte to re-sync",
                                peer_addr,
                            );
                            self.buffer.drain(..1);
                            continue;
                        }

                        break;
                    }

                    if parsed_frames == MAX_FRAMES_PER_READ {
                        warn!(
                            "Reached frame processing cap ({}) for {}, remaining buffered={} bytes",
                            MAX_FRAMES_PER_READ,
                            peer_addr,
                            self.buffer.len(),
                        );
                    }

                    if self.buffer.len() > MAX_STAGED_BUFFER_BYTES {
                        warn!("Buffer too large ({} bytes), clearing", self.buffer.len());
                        self.buffer.clear();
                    }
                }
                Err(e) => {
                    error!("Error reading from client {}: {}", peer_addr, e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_message(&mut self, msg: &DoIpMessage) -> Result<()> {
        let payload_type = msg.payload_type_enum();
        debug!(
            "Received DoIP message: {:?}, payload_len={}",
            payload_type,
            msg.payload.len(),
        );

        match payload_type {
            Some(PayloadType::RoutingActivationRequest) => {
                self.handle_routing_activation(msg).await
            }
            Some(PayloadType::DiagnosticMessage) => self.handle_diagnostic_message(msg).await,
            // TODO(doip): Handle VehicleIdentificationRequest (0x0001..0x0003)
            //   by responding with a VehicleAnnouncementIdentificationResponse
            //   (0x0004) containing VIN, logical address, EID, and GID from config.
            // TODO(doip): Handle AliveCheckRequest (0x0007) by responding with
            //   AliveCheckResponse (0x0008) containing our source address.
            _ => {
                debug!("Unsupported payload type: {:?}", payload_type);
                Ok(())
            }
        }
    }

    async fn handle_routing_activation(&mut self, msg: &DoIpMessage) -> Result<()> {
        let Some(req) = RoutingActivationRequest::from_payload(&msg.payload) else {
            warn!("Invalid routing activation request");
            return Ok(());
        };

        self.session.activate(req.source_address);

        let mut payload = Vec::new();
        payload.extend_from_slice(&req.source_address.to_be_bytes());
        payload.extend_from_slice(&self.config.ecu.logical_address.to_be_bytes());
        payload.push(ROUTING_ACTIVATION_SUCCESS);

        let response = DoIpMessage::new(PayloadType::RoutingActivationResponse, payload);
        self.send_message(&response).await?;

        info!(
            "Routing activated for source address 0x{:04X}",
            req.source_address
        );
        Ok(())
    }

    async fn handle_diagnostic_message(&mut self, msg: &DoIpMessage) -> Result<()> {
        if !self.session.is_activated() {
            warn!("Received diagnostic message before routing activation");
            return Ok(());
        }

        let Some(diag_msg) = DiagnosticMessage::from_payload(&msg.payload) else {
            warn!("Invalid diagnostic message");
            return Ok(());
        };

        debug!(
            "Diagnostic message: SA=0x{:04X}, TA=0x{:04X}, {} bytes",
            diag_msg.source_address,
            diag_msg.target_address,
            diag_msg.user_data.len()
        );

        let expected_target = self.config.ecu.logical_address;
        if diag_msg.target_address != expected_target {
            warn!(
                "Ignoring diagnostic message for unexpected target address 0x{:04X} (expected \
                 0x{:04X})",
                diag_msg.target_address, expected_target,
            );
            return Ok(());
        }

        if !self.session.is_activated_for(diag_msg.source_address) {
            warn!(
                "Ignoring diagnostic message from non-activated source 0x{:04X}",
                diag_msg.source_address,
            );
            return Ok(());
        }

        let uds_response = self.process_uds_request(&diag_msg.user_data).await;
        if uds_response.is_empty() {
            debug!(
                "UDS response suppressed for source 0x{:04X}",
                diag_msg.source_address
            );
            return Ok(());
        }

        let response_payload = DiagnosticMessage::build_payload(
            self.config.server.source_address,
            diag_msg.source_address,
            &uds_response,
        );

        let response = DoIpMessage::new(PayloadType::DiagnosticMessage, response_payload);
        self.send_message(&response).await?;

        Ok(())
    }

    async fn process_uds_request(&self, uds_data: &[u8]) -> Vec<u8> {
        // All supported services require at least SID (1) + DID high (1) + DID low (1).
        if uds_data.len() < MIN_READ_SERVICE_LENGTH {
            error!(
                "UDS request too short: {} byte(s), minimum is {}",
                uds_data.len(),
                MIN_READ_SERVICE_LENGTH,
            );
            return vec![
                service_ids::NEGATIVE_RESPONSE,
                UNKNOWN_SERVICE_ID,
                Nrc::IncorrectMessageLengthOrInvalidFormat as u8,
            ];
        }

        if let Some(&service_id) = uds_data.first() {
            info!(
                "UDS request SID=0x{:02X}, payload_len={} bytes",
                service_id,
                uds_data.len(),
            );
        } else {
            info!("UDS request with empty payload");
        }
        debug!("UDS request payload: {:02X?}", uds_data);

        let uds_msg = match UdsMessage::from_bytes(uds_data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse UDS message: {}", e);
                return vec![
                    service_ids::NEGATIVE_RESPONSE,
                    UNKNOWN_SERVICE_ID,
                    Nrc::IncorrectMessageLengthOrInvalidFormat as u8,
                ];
            }
        };

        match uds_msg.service_id {
            service_ids::READ_DATA_BY_IDENTIFIER => {
                self.process_read_data_by_identifier(&uds_msg).await
            }
            service_ids::WRITE_DATA_BY_IDENTIFIER => {
                self.process_write_data_by_identifier(&uds_msg).await
            }
            // TODO(uds): Add DiagnosticSessionControl (0x10) and
            //   TesterPresent (0x3E) handling — both are required for
            //   compliant UDS communication.  TesterPresent should respond
            //   with a positive response; session control should forward to
            //   the SOVD gateway modes API.
            _ => {
                info!("Unsupported service: 0x{:02X}", uds_msg.service_id);
                uds_msg.build_negative_response(Nrc::ServiceNotSupported)
            }
        }
    }

    async fn process_write_data_by_identifier(&self, uds_msg: &UdsMessage) -> Vec<u8> {
        if uds_msg.data.len() < MIN_WDBI_DATA_LENGTH {
            error!("Invalid write request - missing DID or data");
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        }

        let Some(did_value) = uds_msg.extract_did() else {
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        };

        let uds_request = {
            let mut req = vec![service_ids::WRITE_DATA_BY_IDENTIFIER];
            req.extend_from_slice(&uds_msg.data);
            req
        };

        match self
            .diag_handler
            .handle_write_did(did_value, &uds_request)
            .await
        {
            Ok(uds_response) => uds_response,
            Err(e) => {
                error!("[UDS2SOVD] Write flow failed: {}", e);
                uds_msg.build_negative_response(Nrc::GeneralProgrammingFailure)
            }
        }
    }

    async fn process_read_data_by_identifier(&self, uds_msg: &UdsMessage) -> Vec<u8> {
        if uds_msg.data.len() < MIN_RDBI_DATA_LENGTH {
            error!("Invalid read request - missing DID");
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        }

        let Some(did_value) = uds_msg.extract_did() else {
            return uds_msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        };

        let uds_request = {
            let mut req = vec![service_ids::READ_DATA_BY_IDENTIFIER];
            req.extend_from_slice(uds_msg.data.get(..MIN_RDBI_DATA_LENGTH).unwrap_or_default());
            req
        };

        match self
            .diag_handler
            .handle_read_did(did_value, &uds_request)
            .await
        {
            Ok(uds_response) => uds_response,
            Err(e) => {
                error!("[UDS2SOVD] Read flow failed: {}", e);
                uds_msg.build_negative_response(Nrc::RequestOutOfRange)
            }
        }
    }

    async fn send_message(&mut self, msg: &DoIpMessage) -> Result<()> {
        let bytes = msg.to_bytes();
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uds_message() {
        let bytes = vec![service_ids::READ_DATA_BY_IDENTIFIER, 0xF1, 0x90];
        let msg = UdsMessage::from_bytes(&bytes).expect("failed to parse valid UDS message");
        assert_eq!(msg.service_id, service_ids::READ_DATA_BY_IDENTIFIER);
        assert_eq!(msg.data, vec![0xF1, 0x90]);
    }

    #[test]
    fn test_negative_response() {
        let msg = UdsMessage {
            service_id: service_ids::READ_DATA_BY_IDENTIFIER,
            data: vec![],
        };
        let response = msg.build_negative_response(Nrc::RequestOutOfRange);
        assert_eq!(response, vec![0x7F, 0x22, 0x31]);
    }

    #[test]
    fn test_parse_empty_message() {
        assert!(UdsMessage::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_unknown_service_kept_for_dispatch() {
        let msg = UdsMessage::from_bytes(&[0xFF]).expect("failed to parse single-byte UDS message");
        assert_eq!(msg.service_id, 0xFF);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_write_service_negative_response() {
        let msg = UdsMessage {
            service_id: service_ids::WRITE_DATA_BY_IDENTIFIER,
            data: vec![],
        };
        let response = msg.build_negative_response(Nrc::IncorrectMessageLengthOrInvalidFormat);
        assert_eq!(response, vec![0x7F, 0x2E, 0x13]);
    }

    #[test]
    fn test_invalid_doip_header_detection() {
        let mut raw = vec![0x03, 0xFC, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(has_invalid_doip_header(&raw));

        if let Some(version) = raw.get_mut(0) {
            *version = DOIP_PROTOCOL_VERSION;
        }
        if let Some(inverse) = raw.get_mut(1) {
            *inverse = !DOIP_PROTOCOL_VERSION;
        }
        assert!(!has_invalid_doip_header(&raw));
    }
}
