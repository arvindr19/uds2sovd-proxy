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

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use serde::{Deserialize, Deserializer, de};

use crate::error::{ProxyError, Result};

/// Required byte length for EID and GID fields per ISO 13400-2.
const EID_GID_BYTE_LENGTH: usize = 6;

// Default values for ServerConfig.
const DEFAULT_DOIP_PORT: u16 = 13400;
const DEFAULT_MAX_CONNECTIONS: usize = 10;
/// DoIP source address (tester logical address used in response messages).
const DEFAULT_SOURCE_ADDRESS: u16 = 0x0E80;

// Default values for SovdConfig.
const DEFAULT_GATEWAY_URL: &str = "http://localhost:20002";
const DEFAULT_CLIENT_ID: &str = "uds2sovd_proxy";
const DEFAULT_CLIENT_SECRET: &str = "test_secret";
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_API_VERSION: &str = "v15";

// Default values for EcuConfig.
const DEFAULT_ECU_NAME: &str = "ECU";
/// Top-level proxy configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize, Default)]
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

/// `DoIP` server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// TCP port for the `DoIP` server (default: 13400).
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub doip_port: u16,
    /// IP address to bind the server socket to.
    #[serde(deserialize_with = "deserialize_ip_addr")]
    pub bind_address: IpAddr,
    /// Maximum number of concurrent connections.
    #[serde(deserialize_with = "deserialize_max_connections")]
    pub max_connections: usize,
    /// `DoIP` source address used in response messages.
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub source_address: u16,
}

fn deserialize_nonzero_u16<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    let v = u16::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must not be zero"));
    }
    Ok(v)
}

/// Deserialize IP address string into `std::net::IpAddr`.
fn deserialize_ip_addr<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<IpAddr, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse::<IpAddr>()
        .map_err(|_| de::Error::custom(format!("invalid IP address: {s}")))
}

/// Reject zero during deserialization for `usize` fields.
fn deserialize_max_connections<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<usize, D::Error> {
    let v = usize::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must be greater than zero"));
    }
    Ok(v)
}

/// Reject empty gateway URL strings during deserialization.
fn deserialize_nonempty_gateway_url<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Err(de::Error::custom("gateway_url must not be empty"));
    }
    Ok(s)
}
/// SOVD gateway connection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SovdConfig {
    /// Base URL of the SOVD gateway (e.g. `http://localhost:20002`).
    #[serde(deserialize_with = "deserialize_nonempty_gateway_url")]
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
    #[serde(default = "SovdConfig::default_include_schema")]
    pub include_schema: bool,
    /// When `true`, bypass HTTP calls and generate synthetic responses.
    #[serde(default)]
    pub mock_gateway: bool,
}

impl SovdConfig {
    fn default_include_schema() -> bool {
        true
    }
}

/// ECU identity and addressing configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct EcuConfig {
    /// Default ECU name used for SOVD component path.
    pub default_name: String,
    /// ISO 13400 logical address of the target ECU.
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub logical_address: u16,
    /// 6-byte Entity Identification (MAC address).
    pub eid: [u8; EID_GID_BYTE_LENGTH],
    /// 6-byte Group Identification.
    pub gid: [u8; EID_GID_BYTE_LENGTH],
}

/// Logging output configuration.
#[derive(Debug, Clone, Deserialize)]
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            doip_port: DEFAULT_DOIP_PORT,
            bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            source_address: DEFAULT_SOURCE_ADDRESS,
        }
    }
}

impl Default for SovdConfig {
    fn default() -> Self {
        Self {
            gateway_url: DEFAULT_GATEWAY_URL.to_string(),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_secret: DEFAULT_CLIENT_SECRET.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            api_version: DEFAULT_API_VERSION.to_string(),
            include_schema: true,
            mock_gateway: false,
        }
    }
}

impl Default for EcuConfig {
    fn default() -> Self {
        Self {
            default_name: DEFAULT_ECU_NAME.to_string(),
            logical_address: 0x0001,
            eid: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            gid: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
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
        assert_eq!(config.ecu.eid, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_deserialize_valid_config() {
        let toml_str = r#"
                    [server]
                    doip_port = 13400
                    bind_address = "0.0.0.0"
                    max_connections = 10
                    source_address = 3712

                    [sovd]
                    gateway_url = "http://localhost:20002"
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 1
                    eid = [0, 1, 2, 3, 4, 5]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let config: Config = toml::from_str(toml_str).expect("valid config should parse");
        assert_eq!(config.ecu.eid, [0, 1, 2, 3, 4, 5]);
        assert_eq!(config.server.doip_port, 13400);
    }

    #[test]
    fn test_deserialize_rejects_zero_port() {
        let toml_str = r#"
                    [server]
                    doip_port = 0
                    bind_address = "0.0.0.0"
                    max_connections = 10
                    source_address = 3712

                    [sovd]
                    gateway_url = "http://localhost:20002"
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 1
                    eid = [0, 1, 2, 3, 4, 5]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "doip_port=0 should be rejected");
    }

    #[test]
    fn test_deserialize_rejects_zero_max_connections() {
        let toml_str = r#"
                    [server]
                    doip_port = 13400
                    bind_address = "0.0.0.0"
                    max_connections = 0
                    source_address = 3712

                    [sovd]
                    gateway_url = "http://localhost:20002"
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 1
                    eid = [0, 1, 2, 3, 4, 5]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "max_connections=0 should be rejected");
    }

    #[test]
    fn test_deserialize_rejects_zero_logical_address() {
        let toml_str = r#"
                    [server]
                    doip_port = 13400
                    bind_address = "0.0.0.0"
                    max_connections = 10
                    source_address = 3712

                    [sovd]
                    gateway_url = "http://localhost:20002"
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 0
                    eid = [0, 1, 2, 3, 4, 5]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "logical_address=0 should be rejected");
    }

    #[test]
    fn test_deserialize_rejects_wrong_eid_length() {
        let toml_str = r#"
                    [server]
                    doip_port = 13400
                    bind_address = "0.0.0.0"
                    max_connections = 10
                    source_address = 3712

                    [sovd]
                    gateway_url = "http://localhost:20002"
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 1
                    eid = [0, 1, 2]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "eid with wrong length should be rejected");
    }

    #[test]
    fn test_deserialize_rejects_empty_gateway_url() {
        let toml_str = r#"
                    [server]
                    doip_port = 13400
                    bind_address = "0.0.0.0"
                    max_connections = 10
                    source_address = 3712

                    [sovd]
                    gateway_url = ""
                    client_id = "test"
                    client_secret = "secret"
                    timeout_ms = 5000
                    api_version = "v15"

                    [ecu]
                    default_name = "ECU"
                    logical_address = 1
                    eid = [0, 1, 2, 3, 4, 5]
                    gid = [0, 1, 2, 3, 4, 5]

                    [logging]
                    level = "info"
                    format = "pretty"
                    "#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "empty gateway_url should be rejected");
    }
}
