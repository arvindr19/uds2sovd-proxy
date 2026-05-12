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

use cda_interfaces::service_ids;
use proxy_core::{
    Config, ServiceResolver,
    error::{Result, SovdError},
};
use serde_json::{Map, Value};

use crate::{client::SovdClient, schema::DataResponse};

/// Minimum total WDBI UDS request length: SID (1) + DID high (1) + DID low (1).
/// A valid write request must contain at least one data byte beyond this header.
const MIN_WDBI_REQUEST_HEADER_LENGTH: usize = 3;

/// Translates UDS diagnostic requests into SOVD REST calls and back.
///
/// Handles both `ReadDataByIdentifier` (RDBI) and `WriteDataByIdentifier` (WDBI)
/// requests by forwarding them to the SOVD gateway and encoding/decoding
/// the JSON <-> UDS byte mappings via MDD metadata.
///
/// # Current scope
///
/// Read and write services with mocked SOVD gateway responses.  The mock
/// path generates synthetic JSON from MDD POS-RESPONSE metadata, then
/// encodes it back to UDS bytes — exercising the full translation pipeline
/// without requiring a live SOVD server.
///
/// - TODO(sovd): When the SOVD server returns real responses, remove the
///   mock path and the `generate_mock_response_data` logic in [`SovdClient`].
/// - TODO(sovd): Handle SOVD `errors[]` array in [`DataResponse`] — map
///   field-level errors to UDS negative responses.
/// - TODO(sovd): Forward parsed request data to the SOVD gateway for
///   write requests that need request-parameter context.
pub struct SovdMapper {
    /// ECU component name used in SOVD REST paths.
    ecu_name: String,
    /// When `true`, bypass HTTP and generate synthetic responses.
    mock_gateway: bool,
    /// Base URL of the SOVD gateway
    gateway_url: String,
    /// SOVD API version path segment
    api_version: String,
    /// HTTP client for the SOVD gateway.
    sovd_client: SovdClient,
}

impl SovdMapper {
    #[must_use]
    pub fn new(config: &Config, sovd_client: SovdClient) -> Self {
        Self {
            ecu_name: config.ecu.default_name.clone(),
            mock_gateway: config.sovd.mock_gateway,
            gateway_url: config.sovd.gateway_url.to_string(),
            api_version: config.sovd.api_version.clone(),
            sovd_client,
        }
    }

    /// # Errors
    /// Returns an error if the SOVD read request or UDS encoding fails.
    pub async fn process_read_data_request(
        &self,
        did: u16,
        uds_request: &[u8],
        resolver: &ServiceResolver,
        service_name: &str,
        parsed_data: Option<Map<String, Value>>,
    ) -> Result<Vec<u8>> {
        tracing::debug!(
            "[RDBI] DID 0x{:04X} service='{}' request={:02X?}",
            did,
            service_name,
            uds_request
        );
        if let Some(ref parsed) = parsed_data {
            tracing::trace!(
                "[RDBI] Parsed request: {}",
                serde_json::to_string_pretty(parsed).unwrap_or_default()
            );
        }

        let sovd_endpoint = service_name.to_lowercase();

        let sovd_response = if self.mock_gateway {
            self.mock_read_response(did, service_name, &sovd_endpoint, resolver)
                .await?
        } else {
            // TODO(sovd-server): read path - not exercised while mock_gateway = true.
            let resp = self
                .sovd_client
                .read_data(&self.ecu_name, &sovd_endpoint)
                .await?;
            tracing::debug!(
                "[RDBI] SOVD response for '{}': {:?}",
                sovd_endpoint,
                resp.data
            );
            resp
        };

        let uds_response = self
            .sovd_json_to_uds(did, &sovd_response, resolver, service_name)
            .await?;

        tracing::info!(
            "[RDBI] DID 0x{:04X} '{}' -> {} bytes: {:02X?}",
            did,
            service_name,
            uds_response.len(),
            uds_response
        );
        Ok(uds_response)
    }

    /// # Errors
    /// Returns an error if the SOVD write request fails.
    pub async fn process_write_data_request(
        &self,
        did: u16,
        uds_request: &[u8],
        service_name: &str,
        parsed_data: Map<String, Value>,
    ) -> Result<Vec<u8>> {
        if uds_request.len() <= MIN_WDBI_REQUEST_HEADER_LENGTH {
            return Err(SovdError::SchemaMismatch("Write request missing data".to_string()).into());
        }

        let sovd_endpoint = service_name.to_lowercase();

        tracing::debug!(
            "[WDBI] SOVD JSON data: {}",
            serde_json::to_string_pretty(&parsed_data).unwrap_or_default()
        );

        self.sovd_client
            .write_data(&self.ecu_name, &sovd_endpoint, parsed_data)
            .await?;

        let uds_response = vec![
            service_ids::WRITE_DATA_BY_IDENTIFIER | cda_interfaces::UDS_ID_RESPONSE_BITMASK,
            (did >> 8) as u8,
            (did & 0xFF) as u8,
        ];

        tracing::info!(
            "[WDBI] DID 0x{:04X} '{}' -> {} bytes",
            did,
            service_name,
            uds_response.len()
        );
        Ok(uds_response)
    }

    /// Bypass the live SOVD gateway and return a synthetic [`DataResponse`].
    ///
    /// Builds the response JSON entirely from MDD POS-RESPONSE metadata so
    /// the full UDS translation pipeline can be exercised without a running
    /// SOVD server.  Logs the URL that would have been called so the mock
    /// path is easy to spot in traces.
    ///
    /// # Errors
    /// Returns an error if no POS-RESPONSE metadata is available for the
    /// requested service.
    async fn mock_read_response(
        &self,
        did: u16,
        service_name: &str,
        sovd_endpoint: &str,
        resolver: &ServiceResolver,
    ) -> Result<DataResponse> {
        let would_be_url = format!(
            "{}/vehicle/{}/components/{}/data/{}",
            self.gateway_url, self.api_version, self.ecu_name, sovd_endpoint
        );
        tracing::info!(
            "[SOVD MOCK] GET {} (intercepted —> generating synthetic response)",
            would_be_url
        );

        let meta = resolver
            .get_response_metadata(service_name, did)
            .await
            .map_err(|e| {
                SovdError::SchemaMismatch(format!(
                    "Failed to load POS-RESPONSE metadata for '{service_name}': {e}"
                ))
            })?;

        if meta.is_empty() {
            return Err(SovdError::SchemaMismatch(format!(
                "No POS-RESPONSE metadata available for '{service_name}' in mock mode"
            ))
            .into());
        }

        let data = self
            .sovd_client
            .generate_mock_response_data(sovd_endpoint, &meta, did);

        tracing::debug!(
            "[SOVD MOCK] Generated response SOVD JSON data:\n{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );

        Ok(DataResponse::new(sovd_endpoint.to_string(), data))
    }

    /// Convert a SOVD JSON response into raw UDS response bytes.
    ///
    /// Delegates encoding to [`ResponseEncoder`], which uses MDD POS-RESPONSE
    /// parameter metadata to place each field at its correct byte offset.
    ///
    /// # Errors
    /// Returns an error if the MDD encoder cannot produce a valid response
    /// for the given service name.
    async fn sovd_json_to_uds(
        &self,
        did: u16,
        sovd_response: &DataResponse,
        resolver: &ServiceResolver,
        service_name: &str,
    ) -> Result<Vec<u8>> {
        use cda_interfaces::HashMap as CdaHashMap;

        let mut response_data: CdaHashMap<String, Value> = CdaHashMap::default();

        for (k, v) in &sovd_response.data {
            response_data.insert(k.clone(), v.clone());
        }

        let uds_bytes = resolver
            .build_response(
                service_name,
                service_ids::READ_DATA_BY_IDENTIFIER,
                did,
                response_data,
            )
            .await
            .map_err(|e| {
                SovdError::SchemaMismatch(format!(
                    "MDD failed to encode response for '{service_name}': {e}"
                ))
            })?;

        tracing::debug!(
            "[MDD] SOVD JSON -> UDS for '{}': {:02X?}",
            service_name,
            uds_bytes
        );

        Ok(uds_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_mapper() -> SovdMapper {
        let config = Config::default();
        let sovd_client =
            SovdClient::new(config.sovd.clone()).expect("failed to create SOVD client");
        SovdMapper::new(&config, sovd_client)
    }

    #[test]
    fn test_service_to_sovd_endpoint() {
        assert_eq!("READ_IDENTIFIER".to_lowercase(), "read_identifier");
        assert_eq!("WRITE_IDENTIFIER".to_lowercase(), "write_identifier");
    }

    #[test]
    fn test_mapper_creation() {
        let mapper = create_test_mapper();
        assert!(!mapper.ecu_name.is_empty());
    }
}
