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
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Deserializer, de};
use url::Url;

use crate::error::{ProxyError, Result};

#[derive(Deserialize, Default)]
#[serde(default)]
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

#[derive(Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// TCP port for the `DoIP` server (default: 13 400).
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub doip_port: u16,
    /// IP address to bind the server socket to (default: `0.0.0.0`).
    pub bind_address: IpAddr,
    /// Maximum number of concurrent connections (default: 10).
    #[serde(deserialize_with = "deserialize_max_connections")]
    pub max_connections: usize,
    /// `DoIP` source address used in response messages (default: `0x0E80`).
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub source_address: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            doip_port: 13_400,
            bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_connections: 10,
            source_address: 0x0E80,
        }
    }
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

fn deserialize_max_connections<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<usize, D::Error> {
    let v = usize::deserialize(deserializer)?;
    if v == 0 {
        return Err(de::Error::custom("value must be greater than zero"));
    }
    Ok(v)
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct SovdConfig {
    /// Base URL of the SOVD gateway (e.g. `http://localhost:20002`).
    pub gateway_url: Url,
    /// `OAuth2` client ID for gateway authentication.
    pub client_id: String,
    /// `OAuth2` client secret for gateway authentication.
    pub client_secret: String,
    /// HTTP request timeout in milliseconds.
    pub timeout_ms: u64,
    /// SOVD API version path segment (e.g. `v15`).
    pub api_version: String,
    /// Whether to request inline schema in data responses.
    pub include_schema: bool,
    /// When `true`, bypass HTTP calls and generate synthetic responses.
    pub mock_gateway: bool,
}

impl Default for SovdConfig {
    fn default() -> Self {
        Self {
            gateway_url: "http://localhost:20002"
                .parse()
                .expect("hard-coded URL is always valid"),
            client_id: "uds2sovd_proxy".into(),
            client_secret: "test_secret".into(),
            timeout_ms: 5_000,
            api_version: "v15".into(),
            include_schema: true,
            mock_gateway: true,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
pub struct EidGid([u8; 6]);

impl EidGid {
    fn is_all_zeros(self) -> bool {
        self.0 == [0u8; 6]
    }
}

impl Default for EidGid {
    fn default() -> Self {
        Self([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub struct EcuConfig {
    /// Default ECU name used for SOVD component path.
    pub default_name: String,
    /// ISO 13400 logical address of the target ECU.
    #[serde(deserialize_with = "deserialize_nonzero_u16")]
    pub logical_address: u16,
    /// 6-byte Entity Identification
    pub eid: EidGid,
    /// 6-byte Group Identification.
    pub gid: EidGid,
}

impl Default for EcuConfig {
    fn default() -> Self {
        Self {
            default_name: "ECU".into(),
            logical_address: 0x0001,
            eid: EidGid::default(),
            gid: EidGid::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable coloured output (default).
    #[default]
    Pretty,
    /// Machine-readable JSON (suitable for log aggregators).
    Json,
}

/// Logging output configuration.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level filter.
    pub level: LogLevel,
    /// Output format.
    pub format: LogFormat,
}

/// Any flag set here overrides the corresponding value from the TOML file.
#[derive(Parser)]
#[command(name = "uds2sovd-proxy", version)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        value_name = "FILE",
        env = "PROXY_CONFIG",
        default_value = "config/config.toml"
    )]
    pub config: PathBuf,

    /// Override the IP address to bind to.
    #[arg(long, value_name = "ADDR", env = "PROXY_BIND_ADDRESS")]
    pub bind_address: Option<IpAddr>,

    /// Override the SOVD gateway URL.
    #[arg(long, value_name = "URL", env = "PROXY_GATEWAY_URL")]
    pub gateway_url: Option<Url>,

    /// Enable mock gateway mode (no real HTTP calls).
    #[arg(long, env = "PROXY_MOCK_GATEWAY")]
    pub mock_gateway: bool,

    /// Override the log level.
    #[arg(long, value_enum, value_name = "LEVEL", env = "PROXY_LOG_LEVEL")]
    pub log_level: Option<LogLevel>,

    /// Override the log output format.
    #[arg(long, value_enum, value_name = "FORMAT", env = "PROXY_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// MDD file to load (absolute path, or filename resolved under `--mdd-dir`).
    #[arg(short, long)]
    pub mdd_file: PathBuf,

    /// Directory searched when `--mdd-file` is a relative filename.
    #[arg(long, default_value = "testcontainer/mdd")]
    pub mdd_dir: PathBuf,
}

impl Config {
    /// Build a fully-validated [`Config`] by layering defaults, a TOML file,
    /// and CLI overrides.
    ///
    /// # Layer order
    /// 1. [`Default`] values
    /// 2. TOML file at the path given by `cli.config`
    /// 3. CLI flags
    ///
    /// # Errors
    /// Returns [`ProxyError::Config`] if the TOML file cannot be read/parsed
    /// or if the merged configuration fails validation.
    pub fn load(cli: &Cli) -> Result<Self> {
        // defaults + TOML file
        let mut config = if cli.config.exists() {
            Self::from_file(&cli.config)?
        } else {
            Self::default()
        };

        // CLI overrides
        if let Some(addr) = cli.bind_address {
            config.server.bind_address = addr;
        }
        if let Some(ref url) = cli.gateway_url {
            config.sovd.gateway_url = url.clone();
        }
        if cli.mock_gateway {
            config.sovd.mock_gateway = true;
        }
        if let Some(level) = cli.log_level {
            config.logging.level = level;
        }
        if let Some(format) = cli.log_format {
            config.logging.format = format;
        }

        config.validate()?;
        Ok(config)
    }

    /// Load and validate configuration from a TOML file (without CLI overrides).
    ///
    /// # Errors
    /// Returns [`ProxyError::Config`] if the file cannot be read, parsed, or
    /// if the resulting configuration fails validation.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(format!("cannot read `{}`: {e}", path.display())))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| ProxyError::Config(format!("cannot parse `{}`: {e}", path.display())))?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the fully-merged configuration.
    fn validate(&self) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        if self.server.max_connections == 0 {
            errors.push("[server] max_connections must be greater than zero".into());
        }
        if self.sovd.client_id.is_empty() {
            errors.push("[sovd] client_id must not be empty".into());
        }
        if self.sovd.api_version.is_empty() {
            errors.push("[sovd] api_version must not be empty".into());
        }
        if self.ecu.default_name.is_empty() {
            errors.push("[ecu] default_name must not be empty".into());
        }
        if self.ecu.eid.is_all_zeros() {
            errors.push("[ecu] eid must not be all zeros".into());
        }
        if self.ecu.gid.is_all_zeros() {
            errors.push("[ecu] gid must not be all zeros".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProxyError::Config(format!(
                "configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eid_gid_holds_expected_bytes() {
        let eid = EidGid([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(eid.0, [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    }

    #[test]
    fn eid_gid_all_zeros_detected() {
        let eid = EidGid([0u8; 6]);
        assert!(eid.is_all_zeros());

        let eid2 = EidGid([0, 1, 2, 3, 4, 5]);
        assert!(!eid2.is_all_zeros());
    }

    #[test]
    fn log_level_deserializes_all_variants_from_toml() {
        #[derive(Deserialize)]
        struct Wrapper {
            level: LogLevel,
        }

        for (raw, expected) in [
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
        ] {
            let parsed: Wrapper =
                toml::from_str(&format!("level = \"{raw}\"")).expect("valid level");
            assert_eq!(parsed.level, expected);
        }
    }

    #[test]
    fn log_format_deserializes_all_variants_from_toml() {
        #[derive(Deserialize)]
        struct Wrapper {
            format: LogFormat,
        }

        for (raw, expected) in [("pretty", LogFormat::Pretty), ("json", LogFormat::Json)] {
            let parsed: Wrapper =
                toml::from_str(&format!("format = \"{raw}\"")).expect("valid format");
            assert_eq!(parsed.format, expected);
        }
    }

    #[test]
    fn server_defaults_are_sane() {
        let s = ServerConfig::default();
        assert_eq!(s.doip_port, 13_400);
        assert_eq!(s.max_connections, 10);
    }

    #[test]
    fn sovd_defaults_are_sane() {
        let s = SovdConfig::default();
        assert!(s.mock_gateway);
        assert!(s.include_schema);
        assert_eq!(s.timeout_ms, 5_000);
    }

    #[test]
    fn validation_rejects_empty_client_id() {
        let mut config = Config::default();
        config.sovd.client_id = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_all_zero_eid() {
        let mut config = Config::default();
        config.ecu.eid = EidGid([0u8; 6]);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_max_connections() {
        let mut config = Config::default();
        config.server.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_accumulates_multiple_errors() {
        let mut config = Config::default();
        config.sovd.client_id = String::new();
        config.sovd.api_version = String::new();
        config.ecu.eid = EidGid([0u8; 6]);
        let err = config.validate().unwrap_err().to_string();
        // Three separate bullets should appear.
        assert_eq!(err.matches("  - ").count(), 3);
    }

    #[test]
    fn toml_parses_complete_config() {
        let raw = r#"
[server]
bind_address   = "127.0.0.1"
max_connections = 5
source_address = 3712

[sovd]
gateway_url  = "http://localhost:20002"
client_id    = "test"
client_secret = "secret"
timeout_ms   = 3000
api_version  = "v15"
include_schema = false
mock_gateway   = true

[ecu]
default_name    = "TEST_ECU"
logical_address = 1
eid = [0, 1, 2, 3, 4, 5]
gid = [0, 1, 2, 3, 4, 5]

[logging]
level  = "debug"
format = "json"
"#;
        let cfg: Config = toml::from_str(raw).expect("valid TOML");
        assert!(cfg.sovd.mock_gateway);
        assert_eq!(cfg.logging.level, LogLevel::Debug);
        assert_eq!(cfg.logging.format, LogFormat::Json);
    }

    #[test]
    fn deserialize_rejects_zero_max_connections() {
        let toml_str = r#"
[server]
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
    fn deserialize_rejects_zero_logical_address() {
        let toml_str = r#"
[server]
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
    fn deserialize_rejects_wrong_eid_length() {
        let toml_str = r#"
[server]
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
    fn deserialize_rejects_invalid_gateway_url() {
        let toml_str = r#"
[server]
bind_address = "0.0.0.0"
max_connections = 10
source_address = 3712

[sovd]
gateway_url = "not a valid url"
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
        assert!(result.is_err(), "invalid gateway_url should be rejected");
    }

    #[test]
    fn deserialize_rejects_invalid_log_level() {
        let toml_str = r#"
[server]
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
level = "verbose"
format = "pretty"
"#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err(), "invalid log level should be rejected");
    }

    // ── CLI integration ───────────────────────────────────────────────────

    #[test]
    fn cli_overrides_default_values() {
        let cli = Cli::parse_from([
            "uds2sovd-proxy",
            "--config",
            "/nonexistent/path.toml",
            "--log-level",
            "debug",
            "--mock-gateway",
            "--mdd-file",
            "test.mdd",
        ]);

        let config = Config::load(&cli).expect("should build from defaults + CLI");
        assert_eq!(config.logging.level, LogLevel::Debug);
        assert!(config.sovd.mock_gateway);
    }

    #[test]
    fn toml_with_missing_sections_uses_defaults() {
        let raw = r#"
[server]
bind_address = "127.0.0.1"
max_connections = 5
source_address = 3712
"#;
        let cfg: Config = toml::from_str(raw).expect("partial TOML should parse");
        assert_eq!(cfg.sovd.api_version, "v15");
        assert_eq!(cfg.logging.level, LogLevel::Info);
    }
}
