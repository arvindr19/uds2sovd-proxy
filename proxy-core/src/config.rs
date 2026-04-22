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

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ProxyError, Result};

/// Required byte length for EID and GID fields per ISO 13400-2.
const EID_GID_BYTE_LENGTH: usize = 6;

fn default_true() -> bool {
    true
}

/// Top-level proxy configuration loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// `DoIP` server settings (port, bind address, source address).
    pub server: ServerConfig,
    /// SOVD gateway connection settings.
    pub sovd: SovdConfig,
    /// ECU identity and addressing settings.
    pub ecu: EcuConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
}

/// TODO: `DoIP` server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// TCP port for the `DoIP` server (default: 13400).
    pub doip_port: u16,
    /// IP address to bind the server socket to.
    pub bind_address: String,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// `DoIP` source address used in response messages.
    pub source_address: u16,
}

/// SOVD gateway connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovdConfig {
    /// Base URL of the SOVD gateway (e.g. `http://localhost:20002`).
    pub gateway_url: String,
    /// `OAuth2` client ID for gateway authentication.
    pub client_id: String,
    /// `OAuth2` client secret for gateway authentication.
    pub client_secret: String,
    /// HTTP request timeout in milliseconds.
    pub timeout_ms: u64,
    /// SOVD API version path segment (e.g. `v15`).
    pub api_version: String,
    /// Whether to request inline schema in data responses.
    #[serde(default = "default_true")]
    pub include_schema: bool,
    /// When `true`, bypass HTTP calls and generate synthetic responses.
    #[serde(default)]
    pub mock_gateway: bool,
}

/// ECU identity and addressing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcuConfig {
    /// Default ECU name used for SOVD component path.
    pub default_name: String,
    /// ISO 13400 logical address of the target ECU.
    pub logical_address: u16,
    /// 6-byte Entity Identification (MAC address).
    pub eid: Vec<u8>,
    /// 6-byte Group Identification.
    pub gid: Vec<u8>,
}

/// Logging output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (e.g. `info`, `debug`, `trace`).
    pub level: String,
    /// Output format: `pretty` (default) or `json`.
    pub format: String,
}

impl Config {
    /// Load configuration from TOML file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;

        toml::from_str(&content)
            .map_err(|e| ProxyError::Config(format!("Failed to parse config: {e}")))
    }

    /// Validate configuration
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid.
    ///
    /// TODO(config): Validate `gateway_url` is a well-formed URL, not just
    ///   non-empty.  Consider using the `url` crate for parsing.
    /// TODO(config): Validate `api_version` matches expected pattern (e.g. `v\\d+`).
    pub fn validate(&self) -> Result<()> {
        if self.server.doip_port == 0 {
            return Err(ProxyError::Config("Invalid DoIP port".to_string()));
        }

        if self.sovd.gateway_url.is_empty() && !self.sovd.mock_gateway {
            return Err(ProxyError::Config("SOVD gateway URL is empty".to_string()));
        }

        if self.ecu.eid.len() != EID_GID_BYTE_LENGTH {
            return Err(ProxyError::Config("EID must be 6 bytes".to_string()));
        }

        if self.ecu.gid.len() != EID_GID_BYTE_LENGTH {
            return Err(ProxyError::Config("GID must be 6 bytes".to_string()));
        }

        if self.server.max_connections == 0 {
            return Err(ProxyError::Config(
                "max_connections must be greater than 0".to_string(),
            ));
        }

        if self.ecu.logical_address == 0 {
            return Err(ProxyError::Config(
                "ECU logical address must not be 0x0000".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                doip_port: 13400,
                bind_address: "0.0.0.0".to_string(),
                max_connections: 10,
                source_address: 0x0E80,
            },
            sovd: SovdConfig {
                gateway_url: "http://localhost:20002".to_string(),
                client_id: "uds2sovd_proxy".to_string(),
                client_secret: "test_secret".to_string(),
                timeout_ms: 5000,
                api_version: "v15".to_string(),
                include_schema: true,
                mock_gateway: false,
            },
            ecu: EcuConfig {
                default_name: "ECU".to_string(),
                logical_address: 0x0001,
                eid: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                gid: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "pretty".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.doip_port, 13400);
        assert_eq!(config.sovd.api_version, "v15");
    }

    #[test]
    fn test_validate_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
}
