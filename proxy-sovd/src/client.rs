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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{ParameterTypeMetadata, ResponseParameterInfo};
use proxy_core::{
    config::SovdConfig,
    error::{Result, SovdError},
    service_resolver::find_mux_case_prefix,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::RwLock;

use crate::schema::DataResponse;

/// `OAuth2` token request body.
#[derive(Serialize)]
struct AuthRequest {
    client_id: String,
    client_secret: String,
}

/// `OAuth2` token response body.
#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
}

/// SOVD write request body.
#[derive(Serialize)]
struct WriteDataRequest {
    data: Value,
}

/// HTTP client for communicating with a SOVD gateway.
///
/// Handles authentication, data reads, and data writes against the
/// SOVD REST API.  Supports a mock mode for offline testing.
pub struct SovdClient {
    /// SOVD gateway connection settings.
    config: SovdConfig,
    /// HTTP client with configured timeouts.
    client: Client,
    /// Cached `OAuth2` access token
    access_token: Arc<RwLock<Option<String>>>,
}

impl SovdClient {
    /// Create a new SOVD client with the given configuration.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(config: SovdConfig) -> Result<Self> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| SovdError::Http(e.to_string()))?;

        Ok(Self {
            config,
            client,
            access_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Authenticate with the SOVD gateway and cache the access token.
    ///
    /// # Errors
    /// Returns an error if authentication fails.
    pub async fn authenticate(&self) -> Result<String> {
        if self.config.mock_gateway {
            let token = "mock-access-token".to_string();
            *self.access_token.write().await = Some(token.clone());
            tracing::info!("[SOVD] Mock authentication enabled");
            return Ok(token);
        }

        // TODO(sovd-server): OAuth2 token exchange - only reached when mock_gateway = false.
        let url = format!(
            "{}/vehicle/{}/authorize",
            self.config.gateway_url, self.config.api_version
        );

        let auth_req = AuthRequest {
            client_id: self.config.client_id.clone(),
            client_secret: self.config.client_secret.clone(),
        };

        let response = self
            .client
            .post(&url)
            .json(&auth_req)
            .send()
            .await
            .map_err(|e| SovdError::Http(e.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SovdError::Auth(format!("HTTP {status}: {body}")).into());
        }

        let auth_resp: AuthResponse = response
            .json()
            .await
            .map_err(|e| SovdError::Http(e.to_string()))?;

        *self.access_token.write().await = Some(auth_resp.access_token.clone());
        Ok(auth_resp.access_token)
    }

    /// Return a cached access token, or fetch a fresh one by calling [`authenticate`].
    ///
    /// The token is stored in a shared read-write lock so concurrent requests
    /// can read it without blocking each other. A new token is only requested
    /// when the cache is empty.
    ///
    /// # Errors
    /// Propagates any error returned by [`authenticate`].
    // TODO(sovd-server): token cache helper - only called from the read_data / write_data
    // paths that are bypassed when mock_gateway = true.
    async fn get_token(&self) -> Result<String> {
        {
            let token_guard = self.access_token.read().await;
            if let Some(token) = token_guard.as_ref() {
                return Ok(token.clone());
            }
        }
        self.authenticate().await
    }

    /// Read diagnostic data from the SOVD gateway.
    ///
    /// # Errors
    /// Returns an error if the read request fails.
    ///
    /// # Note
    /// Not called when `mock_gateway = true` - [`SovdMapper`] intercepts the request
    /// in [`SovdMapper::mock_read_response`] before reaching this function.
    // TODO(sovd-server): placeholder - wire up once a real SOVD server is available.
    pub async fn read_data(&self, component: &str, data_id: &str) -> Result<DataResponse> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/vehicle/{}/components/{}/data/{}",
            self.config.gateway_url, self.config.api_version, component, data_id
        );

        tracing::info!("[SOVD] GET {}", url);

        let mut request = self.client.get(&url).bearer_auth(&token);
        if self.config.include_schema {
            request = request.query(&[("include_schema", "true")]);
        }

        let response = request
            .send()
            .await
            .map_err(|e| SovdError::Http(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                tracing::info!("[SOVD] Response: HTTP 200 OK");
                let data: DataResponse = response
                    .json()
                    .await
                    .map_err(|e| SovdError::Http(e.to_string()))?;
                tracing::debug!("[SOVD] Data: {} = {:?}", data.id, data.data);
                Ok(data)
            }
            StatusCode::NOT_FOUND => Err(SovdError::DataIdNotFound(data_id.to_string()).into()),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::Http(format!("HTTP {status}: {body}")).into())
            }
        }
    }

    /// Write diagnostic data to the SOVD gateway.
    ///
    /// # Errors
    /// Returns an error if the write request fails.
    pub async fn write_data(
        &self,
        component: &str,
        data_id: &str,
        data: serde_json::Map<String, Value>,
    ) -> Result<()> {
        if self.config.mock_gateway {
            // SID 0x2E (WriteDataByIdentifier) maps to SOVD /configurations/{service}
            tracing::info!(
                "[SOVD MOCK] PUT /components/{}/configurations/{}",
                component,
                data_id
            );
            return Ok(());
        }

        // TODO(sovd-server): real HTTP PUT - only reached when mock_gateway = false.
        let token = self.get_token().await?;

        let url = format!(
            "{}/vehicle/{}/components/{}/configurations/{}",
            self.config.gateway_url, self.config.api_version, component, data_id
        );

        tracing::info!("[SOVD] PUT {}", url);

        let write_req = WriteDataRequest {
            data: Value::Object(data),
        };

        let response = self
            .client
            .put(&url)
            .bearer_auth(&token)
            .json(&write_req)
            .send()
            .await
            .map_err(|e| SovdError::Http(e.to_string()))?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::ACCEPTED => {
                tracing::info!("[SOVD] Write successful: HTTP {}", response.status());
                Ok(())
            }
            StatusCode::BAD_REQUEST => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::SchemaMismatch(format!("Invalid request: {body}")).into())
            }
            StatusCode::NOT_FOUND => Err(SovdError::DataIdNotFound(data_id.to_string()).into()),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SovdError::Http(format!("HTTP {status}: {body}")).into())
            }
        }
    }

    /// Generate a mock SOVD response from MDD POS-RESPONSE metadata.
    ///
    /// For each VALUE/PhysConst parameter in the response structure, emits a
    /// realistic default derived from the ODX parameter definition:
    ///
    /// - **`PhysConst`**: uses the `coded_value` from MDD (e.g. diagnostic
    ///   session `1` for default session).
    /// - **VALUE with known `byte_size`**: uses a sensible value for the
    ///   field width (e.g. VIN string for 17-byte fields, small counters
    ///   for 1-2 byte fields).
    /// - **`CodedConst` / `MatchingRequestParam`**: skipped — the MDD response
    ///   encoder fills those automatically.
    ///
    /// When the service uses MUX cases, only parameters belonging to the
    /// case that matches `did` are included.
    /// TODO(sovd-server): Remove this function once sovd-server provides real responses.
    #[must_use]
    pub fn generate_mock_response_data(
        &self,
        _data_id: &str,
        response_meta: &[ResponseParameterInfo],
        did: u16,
    ) -> Map<String, Value> {
        // Find the MUX case prefix matching this DID using floor-based matching.
        // Response MUX cases store only the lower_limit as coded_value, so
        // range cases (e.g. a case with lower=61697) need floor matching
        // for DIDs like 0xF103 (61699) that fall within the range.
        let mux_case_prefix = find_mux_case_prefix(response_meta, did);

        // Detect truly opaque response layouts: after MUX filtering, a single
        // VALUE parameter with unknown size carries the whole payload blob.
        let active_value_like: Vec<&ResponseParameterInfo> = response_meta
            .iter()
            .filter(|p| {
                if p.name.starts_with("__mux_case__/") {
                    return false;
                }
                if p.name.contains('/') {
                    match &mux_case_prefix {
                        Some(prefix) if p.name.starts_with(prefix.as_str()) => {}
                        _ => return false,
                    }
                }
                matches!(
                    p.param_type,
                    ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();

        let opaque_single_value = active_value_like.len() == 1
            && active_value_like.first().is_some_and(|p| {
                matches!(p.param_type, ParameterTypeMetadata::Value { .. }) && p.byte_size.is_none()
            });

        let mut data = Map::new();
        for p in response_meta {
            // Skip MUX case markers.
            if p.name.starts_with("__mux_case__/") {
                continue;
            }
            // Skip params from non-matching MUX cases.
            if p.name.contains('/') {
                match &mux_case_prefix {
                    Some(prefix) if p.name.starts_with(prefix.as_str()) => {}
                    _ => continue,
                }
            }
            // Skip coded const and matching request params — encoder fills those.
            match &p.param_type {
                ParameterTypeMetadata::CodedConst { .. }
                | ParameterTypeMetadata::MatchingRequestParam { .. } => {}
                ParameterTypeMetadata::PhysConst { coded_value, .. } => {
                    let key = p.name.rsplit('/').next().unwrap_or(&p.name).to_string();
                    // Use the resolved coded_value from the MDD text-table.
                    let value = coded_value
                        .map(|cv| Value::Number(cv.into()))
                        .unwrap_or_else(|| Value::Number(0.into()));
                    data.insert(key, value);
                }
                ParameterTypeMetadata::Value { .. } => {
                    let key = p.name.rsplit('/').next().unwrap_or(&p.name).to_string();
                    let value = if p.byte_size.is_none() && opaque_single_value {
                        // Opaque STRUCTURE references come through as VALUE with
                        // unknown byte size.  Generate a realistic-length mock
                        // payload based on the DID; the real payload length
                        // comes from the ECU / SOVD server in production.
                        Self::mock_opaque_payload(did)
                    } else {
                        Self::default_value_for_param(p.byte_size)
                    };
                    data.insert(key, value);
                }
            }
        }

        data
    }

    /// Derive a generic default value for a VALUE parameter based on its
    /// byte size only.
    ///
    /// This is MDD-agnostic — no ECU-specific name patterns or DID heuristics.
    /// For small fields (1–8 bytes), produces a numeric equal to the byte
    /// size as a distinguishable non-zero placeholder.  Larger fields are
    /// emitted as zero-filled byte arrays.
    fn default_value_for_param(byte_size: Option<u32>) -> Value {
        match byte_size {
            Some(sz @ 1..=8) => Value::Number(u64::from(sz).into()),
            Some(sz) => {
                // Large fields: zero-filled byte array.
                Value::Array(vec![Value::Number(0.into()); sz as usize])
            }
            None => Value::Number(0.into()),
        }
    }

    /// Generate a generic mock payload for an opaque STRUCTURE parameter
    /// whose `byte_size` is unknown (END-OF-PDU / variable-length).
    ///
    /// Uses a fixed conservative size (4 bytes of zeros) that satisfies the
    /// MDD response encoder without assuming any ECU-specific layout.
    /// Return a fixed-size opaque byte array for services whose response
    /// layout cannot be inferred from metadata
    fn mock_opaque_payload(_did: u16) -> Value {
        const DEFAULT_OPAQUE_SIZE: usize = 4;
        Value::Array(vec![Value::Number(0.into()); DEFAULT_OPAQUE_SIZE])
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn create_test_config() -> SovdConfig {
        SovdConfig {
            gateway_url: "http://localhost:20002".to_string(),
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            timeout_ms: 5000,
            api_version: "v15".to_string(),
            include_schema: true,
            mock_gateway: false,
        }
    }

    #[test]
    fn test_create_client() {
        let config = create_test_config();
        assert!(SovdClient::new(config).is_ok());
    }

    #[test]
    fn test_auth_request_serialization() {
        let auth_req = AuthRequest {
            client_id: "test".to_string(),
            client_secret: "secret".to_string(),
        };
        let json_str = serde_json::to_string(&auth_req).expect("failed to serialize auth request");
        assert!(json_str.contains("test"));
    }

    #[test]
    fn test_write_data_request_serialization() {
        let write_req = WriteDataRequest {
            data: json!({"VIN": "ABC12345678901234"}),
        };
        let json_str =
            serde_json::to_string(&write_req).expect("failed to serialize write request");
        assert!(json_str.contains("ABC12345678901234"));
    }

    #[test]
    fn test_data_response_deserialization() {
        let json_str = r#"{
            "id": "VIN",
            "data": { "VIN": "ABC12345678901234" }
        }"#;
        let response: DataResponse =
            serde_json::from_str(json_str).expect("failed to deserialize data response");
        assert_eq!(response.id, "VIN");
        assert_eq!(
            response.data.get("VIN").expect("VIN field not found"),
            &json!("ABC12345678901234")
        );
    }

    #[test]
    fn test_auth_response_deserialization() {
        let json_str = r#"{
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "expires_in": 3600
        }"#;
        let response: AuthResponse =
            serde_json::from_str(json_str).expect("failed to deserialize auth response");
        assert!(response.access_token.starts_with("eyJ"));
    }

    // ── generate_mock_response_data tests ───────────────────────────────

    #[test]
    fn test_mock_includes_value_params_skips_const() {
        let client = SovdClient::new(create_test_config()).expect("failed to create SOVD client");
        let meta = vec![
            ResponseParameterInfo {
                name: "sid".to_string(),
                semantic: Some("SERVICE-ID".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "98".to_string(),
                },
                byte_position: 0,
                bit_position: 0,
                byte_size: Some(1),
            },
            ResponseParameterInfo {
                name: "RDBI_DID".to_string(),
                semantic: Some("DATA-IDENTIFIER".to_string()),
                param_type: ParameterTypeMetadata::MatchingRequestParam { byte_length: 2 },
                byte_position: 1,
                bit_position: 0,
                byte_size: Some(2),
            },
            ResponseParameterInfo {
                name: "NUMBER_OF_XWES".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(1),
            },
            ResponseParameterInfo {
                name: "XWES_RECORDS".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 4,
                bit_position: 0,
                byte_size: None,
            },
        ];

        let data = client.generate_mock_response_data("rsu_mirror_status", &meta, 0x25A4);

        assert!(data.contains_key("NUMBER_OF_XWES"));
        assert!(data.contains_key("XWES_RECORDS"));
        assert!(!data.contains_key("sid"));
        assert!(!data.contains_key("RDBI_DID"));
        // NUMBER_OF_XWES: 1-byte VALUE -> generic default (sz=1 -> 1)
        assert_eq!(data.get("NUMBER_OF_XWES"), Some(&Value::Number(1.into())));
        // XWES_RECORDS: no byte_size -> 0
        assert_eq!(data.get("XWES_RECORDS"), Some(&Value::Number(0.into())));
    }

    #[test]
    fn test_mock_filters_mux_case() {
        let client = SovdClient::new(create_test_config()).expect("failed to create SOVD client");
        let meta = vec![
            ResponseParameterInfo {
                name: "__mux_case__/case_a".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61840".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(2),
            },
            ResponseParameterInfo {
                name: "__mux_case__/case_b".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61841".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(2),
            },
            ResponseParameterInfo {
                name: "case_a/ADS".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(1),
            },
            ResponseParameterInfo {
                name: "case_b/ADS".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(1),
            },
        ];

        let data = client.generate_mock_response_data("rdbi_ads", &meta, 61840);
        assert!(data.contains_key("ADS"));
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn test_mock_filters_mux_case_float_coded_value() {
        // MDD may store MUX case limits as float-formatted strings (e.g. "61840.0")
        let client = SovdClient::new(create_test_config()).expect("failed to create SOVD client");
        let meta = vec![
            ResponseParameterInfo {
                name: "__mux_case__/case_a".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61840.0".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(2),
            },
            ResponseParameterInfo {
                name: "case_a/ADS".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: Some(1),
            },
        ];

        let data = client.generate_mock_response_data("rdbi_ads", &meta, 61840);
        assert!(
            data.contains_key("ADS"),
            "Float-formatted coded_value must match DID"
        );
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn test_mock_floor_matching_range_mux_case() {
        // Range MUX case: lower_limit 61697 (0xF101) covers DIDs up to next case.
        // DID 0xF103 (61699) should floor-match to this case.
        let client = SovdClient::new(create_test_config()).expect("failed to create SOVD client");
        let meta = vec![
            ResponseParameterInfo {
                name: "__mux_case__/DID_RANGE_F101_F140".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61697".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            ResponseParameterInfo {
                name: "__mux_case__/DID_POINT_F141".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61761".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            ResponseParameterInfo {
                name: "DID_RANGE_F101_F140/DATA".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            ResponseParameterInfo {
                name: "DID_POINT_F141/DATA".to_string(),
                semantic: Some("DATA".to_string()),
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
        ];

        // DID 0xF103 = 61699, floor matches to DID_RANGE_F101_F140 (lower=61697)
        let data = client.generate_mock_response_data("rdbi_did_range", &meta, 0xF103);
        assert!(
            data.contains_key("DATA"),
            "Floor-matched range case should include DATA param"
        );
        assert_eq!(data.len(), 1, "Only DATA from DID_RANGE_F101_F140 case");
        // DID 0xF103: opaque DATA with no byte_size -> generic 4-byte mock payload
        let data_arr = data
            .get("DATA")
            .expect("DATA field not found")
            .as_array()
            .expect("DATA is not an array");
        assert_eq!(data_arr.len(), 4, "Generic opaque mock should be 4 bytes");
    }

    #[test]
    fn test_mock_opaque_payload_is_generic() {
        // All DIDs produce the same conservative 4-byte zero-filled payload.
        let payload = SovdClient::mock_opaque_payload(0xF101);
        let arr = payload.as_array().expect("payload is not an array");
        assert_eq!(arr.len(), 4, "Generic opaque payload should be 4 bytes");
        for v in arr {
            assert_eq!(
                v.as_u64().expect("value is not u64"),
                0,
                "Opaque payload should be zero-filled"
            );
        }

        // Same size for any DID — no ECU-specific table.
        let payload2 = SovdClient::mock_opaque_payload(0x8008);
        let arr2 = payload2.as_array().expect("payload2 is not an array");
        assert_eq!(arr2.len(), 4);
    }

    #[test]
    fn test_default_value_for_param_generic() {
        // 1-byte VALUE -> numeric 1
        assert_eq!(
            SovdClient::default_value_for_param(Some(1)),
            Value::Number(1.into()),
        );
        // 2-byte VALUE -> numeric 2
        assert_eq!(
            SovdClient::default_value_for_param(Some(2)),
            Value::Number(2.into()),
        );
        // 17-byte VALUE -> zero-filled array (no VIN heuristic)
        let val = SovdClient::default_value_for_param(Some(17));
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 17);
        // None byte_size -> 0
        assert_eq!(
            SovdClient::default_value_for_param(None),
            Value::Number(0.into()),
        );
    }
}
