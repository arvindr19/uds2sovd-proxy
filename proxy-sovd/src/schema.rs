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

//! SOVD REST API types for the proxy.
//!
//! These types mirror [`sovd_interfaces::ObjectDataItem`] from CDA but add
//! `Deserialize` since the proxy acts as a SOVD **client** (CDA's types only
//! derive `Serialize` because CDA is a SOVD server).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// SOVD data response (mirrors `sovd_interfaces::ObjectDataItem`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataResponse {
    /// Service identifier
    pub id: String,
    /// Response data as JSON object.
    pub data: serde_json::Map<String, Value>,
    /// Field-level errors returned by the sovd-server, if any.
    ///
    /// Parsed from the response but not yet mapped to UDS negative responses.
    // TODO(sovd-server): map sovd-server field errors to NRC codes when live gateway is connected.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<Value>,
    /// Optional inline schema
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub schema: Option<Value>,
}

impl DataResponse {
    /// Create a new `DataResponse` with the given service id and data.
    #[must_use]
    pub fn new(id: String, data: serde_json::Map<String, Value>) -> Self {
        Self {
            id,
            data,
            errors: Vec::new(),
            schema: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_data_response_new() {
        use serde_json::Map;

        let mut data = Map::new();
        data.insert("identifier".to_string(), json!("ABC12345678901234"));

        let response = DataResponse::new("read_identifier".to_string(), data);

        assert_eq!(response.id, "read_identifier");
        assert_eq!(
            response
                .data
                .get("identifier")
                .expect("identifier field not found"),
            &json!("ABC12345678901234")
        );
        assert!(response.schema.is_none());
        assert!(response.errors.is_empty());
    }

    #[test]
    fn test_data_response_roundtrip() {
        let json_str = r#"{"id":"vin","data":{"VIN":"WBA00000000000001"}}"#;
        let resp: DataResponse =
            serde_json::from_str(json_str).expect("failed to deserialize data response");
        assert_eq!(resp.id, "vin");
        assert_eq!(
            resp.data.get("VIN").and_then(|v| v.as_str()),
            Some("WBA00000000000001")
        );

        let re_serialized =
            serde_json::to_string(&resp).expect("failed to serialize data response");
        assert!(re_serialized.contains("WBA00000000000001"));
    }
}
