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

use thiserror::Error;

/// Top-level error type for the UDS-to-SOVD proxy.
///
/// Covers `DoIP` transport errors, UDS protocol errors, SOVD communication
/// failures, configuration issues, and MDD database problems.
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("DoIP protocol error: {0}")]
    DoIp(String),

    #[error("UDS service error: {0}")]
    Uds(#[from] UdsError),

    #[error("SOVD communication error: {0}")]
    Sovd(#[from] SovdError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("MDD database error: {0}")]
    Mdd(String),
}

/// UDS protocol errors (ISO 14229).
#[derive(Error, Debug)]
pub enum UdsError {
    #[error("Invalid service ID: 0x{0:02X}")]
    InvalidServiceId(u8),

    #[error("Invalid DID: 0x{0:04X}")]
    InvalidDid(u16),

    #[error("Invalid message length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Negative response: NRC 0x{nrc:02X} ({description})")]
    NegativeResponse { nrc: u8, description: String },

    #[error("Unsupported service: 0x{0:02X}")]
    UnsupportedService(u8),
}

/// SOVD gateway communication errors.
#[derive(Error, Debug)]
pub enum SovdError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Component not found: {0}")]
    ComponentNotFound(String),

    #[error("Data identifier not found: {0}")]
    DataIdNotFound(String),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Schema mismatch: {0}")]
    SchemaMismatch(String),
}

/// Convenience result type using [`ProxyError`].
pub type Result<T> = std::result::Result<T, ProxyError>;

/// UDS Negative Response Codes per ISO 14229-1 Table A.1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nrc {
    /// General reject
    GeneralReject = 0x10,
    /// Service not supported
    ServiceNotSupported = 0x11,
    /// Sub-function not supported
    SubFunctionNotSupported = 0x12,
    /// Incorrect message length or invalid format
    IncorrectMessageLengthOrInvalidFormat = 0x13,
    /// Response too long
    ResponseTooLong = 0x14,
    /// Busy - repeat request
    BusyRepeatRequest = 0x21,
    /// Conditions not correct
    ConditionsNotCorrect = 0x22,
    /// Request sequence error
    RequestSequenceError = 0x24,
    /// Request out of range
    RequestOutOfRange = 0x31,
    /// Security access denied
    SecurityAccessDenied = 0x33,
    /// Invalid key
    InvalidKey = 0x35,
    /// Exceeded number of attempts
    ExceededNumberOfAttempts = 0x36,
    /// Required time delay not expired
    RequiredTimeDelayNotExpired = 0x37,
    /// General programming failure
    GeneralProgrammingFailure = 0x72,
}

impl Nrc {
    /// Returns a human-readable description of this NRC.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::GeneralReject => "General reject",
            Self::ServiceNotSupported => "Service not supported",
            Self::SubFunctionNotSupported => "Sub-function not supported",
            Self::IncorrectMessageLengthOrInvalidFormat => {
                "Incorrect message length or invalid format"
            }
            Self::ResponseTooLong => "Response too long",
            Self::BusyRepeatRequest => "Busy - repeat request",
            Self::ConditionsNotCorrect => "Conditions not correct",
            Self::RequestSequenceError => "Request sequence error",
            Self::RequestOutOfRange => "Request out of range",
            Self::SecurityAccessDenied => "Security access denied",
            Self::InvalidKey => "Invalid key",
            Self::ExceededNumberOfAttempts => "Exceeded number of attempts",
            Self::RequiredTimeDelayNotExpired => "Required time delay not expired",
            Self::GeneralProgrammingFailure => "General programming failure",
        }
    }

    /// Convert a raw `u8` NRC value to the corresponding enum variant.
    ///
    /// Returns `None` for unrecognised NRC values.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x10 => Some(Self::GeneralReject),
            0x11 => Some(Self::ServiceNotSupported),
            0x12 => Some(Self::SubFunctionNotSupported),
            0x13 => Some(Self::IncorrectMessageLengthOrInvalidFormat),
            0x14 => Some(Self::ResponseTooLong),
            0x21 => Some(Self::BusyRepeatRequest),
            0x22 => Some(Self::ConditionsNotCorrect),
            0x24 => Some(Self::RequestSequenceError),
            0x31 => Some(Self::RequestOutOfRange),
            0x33 => Some(Self::SecurityAccessDenied),
            0x35 => Some(Self::InvalidKey),
            0x36 => Some(Self::ExceededNumberOfAttempts),
            0x37 => Some(Self::RequiredTimeDelayNotExpired),
            0x72 => Some(Self::GeneralProgrammingFailure),
            _ => None,
        }
    }
}

impl TryFrom<u8> for Nrc {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrc_from_u8_known_codes() {
        assert_eq!(Nrc::from_u8(0x10), Some(Nrc::GeneralReject));
        assert_eq!(Nrc::from_u8(0x11), Some(Nrc::ServiceNotSupported));
        assert_eq!(
            Nrc::from_u8(0x13),
            Some(Nrc::IncorrectMessageLengthOrInvalidFormat)
        );
        assert_eq!(Nrc::from_u8(0x31), Some(Nrc::RequestOutOfRange));
        assert_eq!(Nrc::from_u8(0x33), Some(Nrc::SecurityAccessDenied));
        assert_eq!(Nrc::from_u8(0x72), Some(Nrc::GeneralProgrammingFailure));
    }

    #[test]
    fn test_nrc_from_u8_unknown_codes() {
        assert_eq!(Nrc::from_u8(0x00), None);
        assert_eq!(Nrc::from_u8(0xFF), None);
        assert_eq!(Nrc::from_u8(0x50), None);
    }

    #[test]
    fn test_nrc_description() {
        assert_eq!(Nrc::GeneralReject.description(), "General reject");
        assert_eq!(
            Nrc::ServiceNotSupported.description(),
            "Service not supported"
        );
        assert_eq!(Nrc::RequestOutOfRange.description(), "Request out of range");
    }

    #[test]
    fn test_nrc_repr_values() {
        assert_eq!(Nrc::GeneralReject as u8, 0x10);
        assert_eq!(Nrc::ServiceNotSupported as u8, 0x11);
        assert_eq!(Nrc::SubFunctionNotSupported as u8, 0x12);
        assert_eq!(Nrc::IncorrectMessageLengthOrInvalidFormat as u8, 0x13);
        assert_eq!(Nrc::RequestOutOfRange as u8, 0x31);
        assert_eq!(Nrc::SecurityAccessDenied as u8, 0x33);
    }

    #[test]
    fn test_nrc_roundtrip() {
        let all_nrcs = [
            Nrc::GeneralReject,
            Nrc::ServiceNotSupported,
            Nrc::SubFunctionNotSupported,
            Nrc::IncorrectMessageLengthOrInvalidFormat,
            Nrc::ResponseTooLong,
            Nrc::BusyRepeatRequest,
            Nrc::ConditionsNotCorrect,
            Nrc::RequestSequenceError,
            Nrc::RequestOutOfRange,
            Nrc::SecurityAccessDenied,
            Nrc::InvalidKey,
            Nrc::ExceededNumberOfAttempts,
            Nrc::RequiredTimeDelayNotExpired,
            Nrc::GeneralProgrammingFailure,
        ];
        for nrc in &all_nrcs {
            let byte = *nrc as u8;
            assert_eq!(Nrc::from_u8(byte), Some(*nrc));
            assert!(!nrc.description().is_empty());
        }
    }

    #[test]
    fn test_proxy_error_display() {
        let err = ProxyError::DoIp("connection failed".into());
        assert!(err.to_string().contains("connection failed"));

        let err = ProxyError::Config("invalid port".into());
        assert!(err.to_string().contains("invalid port"));

        let err = ProxyError::Timeout;
        assert!(err.to_string().contains("Timeout"));
    }

    #[test]
    fn test_uds_error_display() {
        let err = UdsError::InvalidServiceId(0xFF);
        assert!(err.to_string().contains("0xFF"));

        let err = UdsError::InvalidDid(0xF190);
        assert!(err.to_string().contains("0xF190"));

        let err = UdsError::InvalidLength {
            expected: 3,
            actual: 1,
        };
        assert!(err.to_string().contains('3'));
        assert!(err.to_string().contains('1'));

        let err = UdsError::NegativeResponse {
            nrc: 0x31,
            description: "Request out of range".into(),
        };
        assert!(err.to_string().contains("0x31"));
    }

    #[test]
    fn test_sovd_error_display() {
        let err = SovdError::Auth("invalid token".into());
        assert!(err.to_string().contains("invalid token"));

        let err = SovdError::ComponentNotFound("ecu1".into());
        assert!(err.to_string().contains("ecu1"));
    }

    #[test]
    fn test_proxy_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let proxy_err: ProxyError = io_err.into();
        assert!(matches!(proxy_err, ProxyError::Io(_)));
    }

    #[test]
    fn test_proxy_error_from_uds() {
        let uds_err = UdsError::InvalidServiceId(0x00);
        let proxy_err: ProxyError = uds_err.into();
        assert!(matches!(proxy_err, ProxyError::Uds(_)));
    }

    #[test]
    fn test_proxy_error_from_sovd() {
        let sovd_err = SovdError::Auth("expired".into());
        let proxy_err: ProxyError = sovd_err.into();
        assert!(matches!(proxy_err, ProxyError::Sovd(_)));
    }
}
