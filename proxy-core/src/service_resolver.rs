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

//! ECU Manager wrapper for MDD-driven UDS request/response processing.
//!
//! Provides a simplified interface to the CDA's
//! `EcuManager` for encoding/decoding UDS messages using the loaded MDD
//! diagnostic database.
//!
//! ## Service resolution
//!
//! When a UDS request arrives the proxy must identify which diagnostic service
//! from the MDD it belongs to (e.g. `WDBI_VIN` vs `WDBI_PLAIN` for SID 0x2E).
//!
//! Resolution uses `lookup_diagcomms_by_request_prefix` with the full
//! `[SID, DID_HI, DID_LO]` prefix, which directly matches services whose
//! sequential coded-const parameters match the request bytes.  This handles
//! CODED-CONST DID services in a single call.
//!
//! For services where the DID is not a coded constant (`PhysConst` / Value),
//! the prefix lookup returns all SID-matching services and the resolver
//! confirms the DID via request parameter metadata:
//!
//!   - **`CodedConst`**: exact DID match.
//!   - **`PhysConst`**: resolved `coded_value` or `create_uds_payload` probe.
//!   - **Value**: `coded_default_value` or `CompuScale` range match.
//!
//! If no service matches, an error is logged — no fallback.

use std::sync::Arc;

use cda_core::{DiagServiceResponseStruct, EcuManager as CdaEcuManager};
use cda_database::datatypes::DiagnosticDatabase;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, DynamicPlugin, EcuManager as EcuManagerTrait,
    EcuManagerType, FunctionalDescriptionConfig, HashMap, MuxCaseInfo, Protocol,
    ServiceParameterMetadata, ServicePayload, UDS_ID_RESPONSE_BITMASK,
    datatypes::{ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition},
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    service_ids,
};
use cda_plugin_security::DefaultSecurityPluginData;
use tokio::sync::RwLock;

/// Minimum UDS negative response length: 0x7F + SID + NRC.
const UDS_NEGATIVE_RESPONSE_MIN_LEN: usize = 3;

/// Minimum UDS positive response buffer size: response SID (1) + DID high (1) + DID low (1).
const UDS_POSITIVE_RESPONSE_MIN_SIZE: usize = 3;

/// Wraps the CDA's [`EcuManager`] with async locking
/// to provide MDD-driven UDS encoding, decoding, and service resolution
/// for the proxy.
pub struct ServiceResolver {
    manager: Arc<RwLock<CdaEcuManager<DefaultSecurityPluginData>>>,
    ecu_name: String,
}

impl ServiceResolver {
    /// Create new ECU manager from MDD database.
    ///
    /// # Arguments
    /// * `ecu_name` - Name of the ECU
    /// * `db` - Loaded `DiagnosticDatabase` from MDD file
    /// * `logical_address` - ECU logical address (e.g. 0x1000)
    /// * `tester_address` - Tester logical address (e.g. 0x0E80)
    ///
    /// # Errors
    /// Returns an error if the ECU manager cannot be initialized from the database.
    pub async fn new(
        ecu_name: String,
        db: DiagnosticDatabase,
        logical_address: u16,
        tester_address: u16,
    ) -> Result<Self, DiagServiceError> {
        let com_params = Self::default_com_params(logical_address, tester_address);

        let func_config = FunctionalDescriptionConfig {
            description_database: String::new(),
            enabled_functional_groups: None,
            protocol_position: DiagnosticServiceAffixPosition::Prefix,
            protocol_case_sensitive: false,
        };

        let mut manager = CdaEcuManager::new(
            db,
            Protocol::DoIp,
            &com_params,
            DatabaseNamingConvention::default(),
            EcuManagerType::Ecu,
            &func_config,
            true,
        )
        .map_err(|e| {
            tracing::error!("Failed to create EcuManager: {}", e);
            e
        })?;

        Self::activate_base_variant(&mut manager).await?;

        Ok(Self {
            manager: Arc::new(RwLock::new(manager)),
            ecu_name,
        })
    }

    /// Activate the base (fallback) ECU variant.
    ///
    /// The CDA's diagnostic engine requires a variant to be selected before
    /// service lookup, metadata queries, or UDS encoding/decoding work
    /// correctly.  When no specific variant is requested (or the requested
    /// variant is not found), this method seeds the engine with a synthetic
    /// dummy response so that `detect_variant` initialises the internal
    /// state-chart and pins the engine to a determinate base state.
    ///
    /// #`TODO:` real variant detection
    ///
    /// Replace the dummy response with actual variant-identification DID
    /// reads from a live ECU connection:
    ///   1. Read variant-identification DIDs from the ECU.
    ///   2. Call `detect_variant(responses)` with real data.
    ///   3. The engine narrows the active variant and limits visible services.
    ///
    /// # Errors
    /// Returns an error only when `detect_variant` fails **and** no variant
    /// name was set (i.e. the engine did not activate at all).
    async fn activate_base_variant(
        manager: &mut CdaEcuManager<DefaultSecurityPluginData>,
    ) -> Result<(), DiagServiceError> {
        // `TODO:` replace this dummy response with real variant-identification
        // DID reads from the ECU (see doc comment above).
        let dummy_response = DiagServiceResponseStruct {
            service: DiagComm {
                name: String::new(),
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            data: vec![],
            mapped_data: None,
            response_type: DiagServiceResponseType::Positive,
        };

        let mut responses: HashMap<String, DiagServiceResponseStruct> = HashMap::default();
        responses.insert("__variant_init__".to_string(), dummy_response);

        match manager.detect_variant(responses).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let variant = manager.variant();
                if variant.name.is_some() {
                    tracing::info!(
                        "Base variant '{}' activated (state chart init skipped: {})",
                        variant.name.as_deref().unwrap_or("unknown"),
                        e
                    );
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Build UDS response bytes from SOVD JSON data using MDD response metadata.
    ///
    /// Queries the POS-RESPONSE parameter layout from the MDD to determine exact
    /// byte positions and sizes for each parameter.  Each parameter is encoded
    /// at its MDD-defined position:
    ///
    /// - **CODED-CONST**: fixed value written directly (e.g. response SID).
    /// - **`MatchingRequestParam`**: DID bytes from the original request.
    /// - **VALUE**: SOVD data value encoded with the correct byte width;
    ///   defaults to 0 when the key is not present in the SOVD response.
    ///
    /// Falls back to naive encoding if response metadata is unavailable.
    ///
    /// # Errors
    /// Returns an error if the response cannot be encoded.
    ///
    /// # TODO:
    /// Once the SOVD server returns properly structured responses, the naive
    /// encoding fallback and the MDD-based `encode_response_from_metadata`
    /// path can be removed — the proxy will forward pre-encoded UDS bytes.
    pub async fn build_response(
        &self,
        service_name: &str,
        sid: u8,
        did: u16,
        response_data: HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        tracing::debug!(
            "[MDD] Building UDS response for '{}' SID 0x{:02X} DID 0x{:04X}",
            service_name,
            sid,
            did,
        );

        let (response, effective_service) = if let Some((r, svc)) = self
            .encode_response_from_metadata(service_name, sid, did, &response_data)
            .await
        {
            (r, svc)
        } else {
            // Fallback: naive encoding — used when no response metadata is available.
            tracing::debug!(
                "[MDD] No response metadata for '{}', using naive encoding",
                service_name
            );
            let response_sid = sid.wrapping_add(UDS_ID_RESPONSE_BITMASK);
            #[allow(clippy::cast_possible_truncation)]
            let mut response = vec![response_sid, (did >> 8) as u8, (did & 0xFF) as u8];

            let entries: Vec<_> = response_data
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("sid"))
                .collect();

            for (key, value) in entries {
                match value {
                    serde_json::Value::String(s) => {
                        response.extend_from_slice(s.as_bytes());
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(num) = n.as_u64() {
                            response.extend(encode_unsigned_be(num));
                        } else if let Some(num) = n.as_i64() {
                            let unsigned = num.cast_unsigned();
                            #[allow(clippy::cast_possible_truncation)]
                            if u8::try_from(unsigned).is_ok() {
                                response.push(unsigned as u8);
                            } else {
                                response.push((unsigned >> 8) as u8);
                                response.push((unsigned & 0xFF) as u8);
                            }
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            #[allow(clippy::cast_possible_truncation)]
                            if let Some(byte) = item.as_u64() {
                                response.push(byte as u8);
                            }
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        response.push(u8::from(*b));
                    }
                    _ => {
                        tracing::warn!(
                            "[MDD] Skipping unsupported value type for '{}': {:?}",
                            key,
                            value
                        );
                    }
                }
            }

            tracing::debug!("[MDD] Built UDS response (naive): {:02X?}", response);
            (response, service_name.to_string())
        };

        // Debug-only round-trip validation: parse the built bytes back through
        // the CDA to confirm the MDD layout produces a decodable
        // response.  Uses the effective service name (which may be an enriched
        // MUX sibling) so the CDA parses against the same structure we
        // encoded with.
        if tracing::enabled!(tracing::Level::DEBUG) {
            self.validate_response(&effective_service, sid, &response)
                .await;
        }

        Ok(response)
    }

    /// Round-trip validate UDS response bytes by parsing them back through
    /// the CDA.
    ///
    /// Called only when `tracing::Level::DEBUG` is enabled — failures are logged
    /// as warnings but never block the response (non-blocking).
    async fn validate_response(&self, service_name: &str, request_sid: u8, uds_response: &[u8]) {
        let diag_comm = self.make_diag_comm(service_name, request_sid);
        let payload = make_service_payload(uds_response);
        let manager = self.manager.read().await;
        match manager.convert_from_uds(&diag_comm, &payload, true).await {
            Ok(parsed) => match parsed.into_json() {
                Ok(json) => tracing::trace!(
                    "[MDD] Round-trip validation OK for '{}': {:?}",
                    service_name,
                    json.data
                ),
                Err(e) => tracing::warn!(
                    "[MDD] Round-trip validation: JSON decode failed for '{}': {}",
                    service_name,
                    e
                ),
            },
            Err(e) => tracing::warn!(
                "[MDD] Round-trip validation: parse failed for '{}': {}",
                service_name,
                e
            ),
        }
    }

    /// Encode a UDS response using POS-RESPONSE parameter metadata from the MDD.
    ///
    /// For each parameter in the MDD response structure:
    /// - CODED-CONST (e.g. response SID at byte 0): writes the const value.
    /// - `MatchingRequestParam` (e.g. DID at bytes 1-2): writes the DID.
    /// - VALUE: uses the SOVD response data keyed by the MDD parameter name;
    ///   falls back to `0` when the key is absent.
    ///
    /// Returns `None` when no response metadata is available for the service.
    /// On success returns the encoded bytes and the effective service name
    /// (which may differ from `service_name` when enriched MUX sibling metadata
    /// is used).
    async fn encode_response_from_metadata(
        &self,
        service_name: &str,
        _sid: u8,
        did: u16,
        response_data: &HashMap<String, serde_json::Value>,
    ) -> Option<(Vec<u8>, String)> {
        let (meta, effective_service) = self
            .get_enriched_response_metadata_with_source(service_name, did)
            .await
            .ok()?;
        if meta.is_empty() {
            return None;
        }

        // Find the MUX case matching this DID (if any) using floor-based matching.
        let mux_case_prefix = find_mux_case_prefix(&meta, did);

        // Derive the matching marker name for total_size computation.
        let mux_marker_name: Option<String> = mux_case_prefix
            .as_deref()
            .map(|pfx| format!("__mux_case__/{}", pfx.trim_end_matches('/')));

        // Filter: keep top-level params (no '/') + matching MUX case VALUE params
        // + the matching case marker (for total_size).
        let active_params: Vec<_> = meta
            .iter()
            .filter(|p| {
                if !p.name.contains('/') {
                    true
                } else if let Some(prefix) = &mux_case_prefix {
                    p.name.starts_with(prefix.as_str())
                        || mux_marker_name.as_deref() == Some(&p.name)
                } else {
                    !p.name.starts_with("__mux_case__/")
                }
            })
            .collect();

        // Resolve effective size for each active param. For VALUE params with
        // `byte_size: None` (variable-length DOPs like EndOfPdu), the size is
        // inferred from the actual response data.
        let effective_sizes: Vec<usize> = active_params
            .iter()
            .map(|p| {
                if let Some(s) = p.byte_size {
                    return s as usize;
                }
                // Variable-size VALUE param — infer size from the data.
                if !matches!(
                    &p.param_type,
                    cda_interfaces::ParameterTypeMetadata::Value { .. }
                ) {
                    return 0;
                }
                let short_name = p.name.rsplit('/').next().unwrap_or(&p.name);
                let value = response_data
                    .get(&p.name)
                    .or_else(|| response_data.get(short_name))
                    .or_else(|| response_data.get(&p.name.to_ascii_lowercase()))
                    .or_else(|| response_data.get(&short_name.to_ascii_lowercase()))
                    .or_else(|| response_data.get("data"));
                value_to_bytes(value).len()
            })
            .collect();

        // Determine total response size from filtered params.
        let total_size = active_params
            .iter()
            .zip(effective_sizes.iter())
            .map(|(p, &sz)| (p.byte_position as usize).saturating_add(sz))
            .max()
            .unwrap_or(UDS_POSITIVE_RESPONSE_MIN_SIZE);

        let mut response = vec![0u8; total_size];

        for (param, &eff_size) in active_params.iter().zip(effective_sizes.iter()) {
            // Skip MUX case markers — they're only used for total_size computation.
            if param.name.starts_with("__mux_case__/") {
                continue;
            }
            let pos = param.byte_position as usize;

            if eff_size == 0 || pos.saturating_add(eff_size) > response.len() {
                continue;
            }

            match &param.param_type {
                cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                    // The SID byte is stored as a decimal string (e.g. "98" for 0x62).
                    if let Ok(val) = coded_value.parse::<u64>() {
                        let bytes = encode_unsigned_be(val);
                        let copy_len = bytes.len().min(eff_size);
                        // Right-align in the field (big-endian convention).
                        let offset = eff_size.saturating_sub(copy_len);
                        let dst_start = pos.saturating_add(offset);
                        let dst_end = dst_start.saturating_add(copy_len);
                        let src_start = bytes.len().saturating_sub(copy_len);
                        if let (Some(dst), Some(src)) =
                            (response.get_mut(dst_start..dst_end), bytes.get(src_start..))
                        {
                            dst.copy_from_slice(src);
                        }
                    }
                }
                cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {
                    // DID bytes from the original request, big-endian.
                    let did_bytes = [(did >> 8) as u8, (did & 0xFF) as u8];
                    let copy_len = did_bytes.len().min(eff_size);
                    if let (Some(dst), Some(src)) = (
                        response.get_mut(pos..pos.saturating_add(copy_len)),
                        did_bytes.get(..copy_len),
                    ) {
                        dst.copy_from_slice(src);
                    }
                }
                cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                    // For MUX case params, try the short name (after '/') as well.
                    let short_name = param.name.rsplit('/').next().unwrap_or(&param.name);
                    let value = response_data
                        .get(&param.name)
                        .or_else(|| response_data.get(short_name))
                        .or_else(|| response_data.get(&param.name.to_ascii_lowercase()))
                        .or_else(|| response_data.get(&short_name.to_ascii_lowercase()))
                        .or_else(|| response_data.get("data"));

                    if param.byte_size.is_some() {
                        encode_value_at(&mut response, pos, eff_size, value);
                    } else {
                        // Variable-size param: write the raw byte representation.
                        let bytes = value_to_bytes(value);
                        let copy_len = bytes.len().min(eff_size);
                        if let (Some(dst), Some(src)) = (
                            response.get_mut(pos..pos.saturating_add(copy_len)),
                            bytes.get(..copy_len),
                        ) {
                            dst.copy_from_slice(src);
                        }
                    }
                }
                cda_interfaces::ParameterTypeMetadata::PhysConst { .. } => {}
            }
        }

        tracing::debug!(
            "[MDD] Built UDS response via metadata for '{}'): {:02X?}",
            service_name,
            response
        );
        Some((response, effective_service))
    }

    /// Parse UDS request bytes using the MDD request structure.
    ///
    /// # Errors
    /// Returns an error if the request cannot be parsed.
    pub async fn parse_request(
        &self,
        service_name: &str,
        uds_request: &[u8],
    ) -> Result<serde_json::Map<String, serde_json::Value>, DiagServiceError> {
        let service_id = uds_request.first().copied().unwrap_or(0x00);
        let diag_comm = self.make_diag_comm(service_name, service_id);
        let payload = make_service_payload(uds_request);

        let manager = self.manager.read().await;
        let response = manager
            .convert_request_from_uds(&diag_comm, &payload, true)
            .await?;
        let json_response = response.into_json()?;

        if let serde_json::Value::Object(map) = json_response.data {
            tracing::debug!(
                "[MDD] Parsed request for '{}': {} fields",
                service_name,
                map.len()
            );
            Ok(map)
        } else {
            tracing::error!(
                "[MDD] Expected JSON object in request, got: {:?}",
                json_response.data
            );
            Err(DiagServiceError::InvalidRequest(
                "Expected JSON object in request".to_string(),
            ))
        }
    }

    /// Retrieve request parameter metadata for a service.
    ///
    /// # Errors
    /// Returns an error if the metadata is not available.
    pub async fn get_service_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<ServiceParameterMetadata>, DiagServiceError> {
        let manager = self.manager.read().await;
        manager.get_request_parameter_metadata(service_name)
    }

    /// Retrieve POS-RESPONSE parameter metadata (byte positions, sizes, types).
    ///
    /// # Errors
    /// Returns an error if the metadata is not available.
    pub async fn get_response_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        let manager = self.manager.read().await;
        manager.get_response_parameter_metadata(service_name)
    }

    /// Retrieve enriched POS-RESPONSE metadata for a service + DID.
    ///
    /// Some services have a direct POS-RESPONSE
    /// that references a STRUCTURE as a single opaque VALUE param (`byte_size` =
    /// None, no sub-fields).  The CDA doesn't flatten the STRUCTURE children in the
    /// metadata for these services.
    ///
    /// However, a shared MUX-based response used by
    /// sibling services DOES flatten every DID's sub-fields.  This method
    /// detects the opaque-STRUCTURE case and transparently returns the richer
    /// MUX-based metadata instead, so callers get per-field byte positions.
    ///
    /// # Errors
    /// Returns an error if the metadata is not available.
    pub async fn get_enriched_response_metadata(
        &self,
        service_name: &str,
        did: u16,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        self.get_enriched_response_metadata_with_source(service_name, did)
            .await
            .map(|(meta, _source)| meta)
    }

    /// Same as [`get_enriched_response_metadata`] but also returns the name of
    /// the service that actually provided the metadata. When the response is
    /// "opaque" (single STRUCTURE ref) and a MUX-based sibling is used, the
    /// returned name is the sibling — callers that need to validate via
    /// `convert_from_uds` must use this name, not the original.
    ///
    async fn get_enriched_response_metadata_with_source(
        &self,
        service_name: &str,
        did: u16,
    ) -> Result<(Vec<cda_interfaces::ResponseParameterInfo>, String), DiagServiceError> {
        let manager = self.manager.read().await;
        let meta = manager.get_response_parameter_metadata(service_name)?;

        // Heuristic: the response is "opaque" when the only data param
        // (after SID + DID) is a single VALUE with byte_size = None.
        let data_params: Vec<_> = meta
            .iter()
            .filter(|p| {
                matches!(
                    p.param_type,
                    cda_interfaces::ParameterTypeMetadata::Value { .. }
                        | cda_interfaces::ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();

        let Some(first_param) = data_params.first() else {
            return Ok((meta, service_name.to_string()));
        };
        let is_opaque = data_params.len() == 1
            && first_param.byte_size.is_none()
            && !first_param.name.contains('/');

        if !is_opaque {
            return Ok((meta, service_name.to_string()));
        }

        tracing::debug!(
            "[MDD] Response metadata for '{}' is opaque (single STRUCTURE ref '{}'), searching \
             for MUX-based sibling",
            service_name,
            first_param.name,
        );

        let security_plugin: DynamicPlugin = Box::new(());

        // Search READ services for a MUX-based sibling with a case for this DID.
        let candidates: Vec<String> = manager
            .get_components_data_info(&security_plugin)
            .into_iter()
            .map(|c| c.id)
            .collect();

        for candidate in &candidates {
            if candidate == service_name {
                continue;
            }
            let sibling_meta = match manager.get_response_parameter_metadata(candidate) {
                Ok(m) if m.len() > meta.len() => m,
                _ => continue,
            };
            // Check if this sibling has a MUX case matching our DID (exact match
            // to avoid cross-DOP false positives from floor matching).
            let has_mux_for_did = has_mux_case_for_did_exact(&sibling_meta, did);
            if has_mux_for_did {
                tracing::debug!(
                    "[MDD] Using MUX-based metadata from '{}' for DID 0x{:04X} ({} params instead \
                     of {})",
                    candidate,
                    did,
                    sibling_meta.len(),
                    meta.len(),
                );
                return Ok((sibling_meta, candidate.clone()));
            }
        }

        // No MUX sibling found — use original metadata.
        Ok((meta, service_name.to_string()))
    }

    /// Look up service names by SID.
    ///
    /// # Errors
    /// Returns an error if the lookup fails.
    pub async fn lookup_service_names_by_sid(
        &self,
        sid: u8,
    ) -> Result<Vec<String>, DiagServiceError> {
        let manager = self.manager.read().await;
        let security_plugin: DynamicPlugin = Box::new(());
        let names = if sid == service_ids::READ_DATA_BY_IDENTIFIER {
            manager
                .get_components_data_info(&security_plugin)
                .into_iter()
                .map(|c| c.id)
                .collect()
        } else if sid == service_ids::WRITE_DATA_BY_IDENTIFIER {
            manager
                .get_components_configurations_info(&security_plugin)
                .map(|v| v.into_iter().map(|c| c.id).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(names)
    }

    /// Retrieve MUX case information for a service.
    ///
    /// # Errors
    /// Returns an error if the metadata is not available.
    pub async fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<MuxCaseInfo>, DiagServiceError> {
        let manager = self.manager.read().await;
        manager.get_mux_cases_for_service(service_name)
    }

    /// Resolve the best-matching READ service for UDS request bytes.
    pub async fn resolve_read_service(
        &self,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
        self.resolve_service(service_ids::READ_DATA_BY_IDENTIFIER, did, uds_bytes, "READ")
            .await
    }

    /// Resolve the best-matching WRITE service for UDS request bytes.
    pub async fn resolve_write_service(
        &self,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
        self.resolve_service(
            service_ids::WRITE_DATA_BY_IDENTIFIER,
            did,
            uds_bytes,
            "WRITE",
        )
        .await
    }

    /// Probe a service DID via request encoding for symbolic PHYS-CONST cases.
    async fn probe_service_did(
        manager: &CdaEcuManager<DefaultSecurityPluginData>,
        service_name: &str,
        sid: u8,
        params: &[ServiceParameterMetadata],
    ) -> Option<u16> {
        let mut param_map: HashMap<String, serde_json::Value> = HashMap::default();
        for param in params {
            match &param.param_type {
                cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                    // `?` is intentional: if any CodedConst can't be parsed we cannot
                    // build a valid probe request, so abort the entire probe.
                    let parsed = parse_u64_literal(coded_value)?;
                    param_map.insert(param.name.clone(), serde_json::json!(parsed));
                }
                cda_interfaces::ParameterTypeMetadata::PhysConst {
                    phys_constant_value,
                    ..
                } => {
                    param_map.insert(param.name.clone(), serde_json::json!(phys_constant_value));
                }
                cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                    // Use string probe value for VALUE params to satisfy DOPs that
                    // parse textual values (TEXTTABLE / string-typed fields).
                    param_map.insert(param.name.clone(), serde_json::json!("0"));
                }
                cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {}
            }
        }

        let diag_comm = DiagComm {
            name: service_name.to_string(),
            type_: diag_comm_type(sid),
            lookup_name: Some(service_name.to_string()),
        };
        let security_plugin: DynamicPlugin = Box::new(());

        let payload = manager
            .create_uds_payload(
                &diag_comm,
                &security_plugin,
                Some(UdsPayloadData::ParameterMap(param_map)),
            )
            .await
            .ok()?;

        let probed_did = extract_did_from_uds(&payload.data)?;
        // ISO 14229-1 §7.3.2: DID 0x0000 is reserved.  A zero result means the
        // Payload encoding produced a degenerate output (e.g. a TEXTTABLE
        // lookup silently failed), so treat it as unresolvable rather than a match.
        if probed_did == 0 {
            None
        } else {
            Some(probed_did)
        }
    }

    /// Resolve a DID to a service name using prefix lookup and metadata.
    ///
    /// Uses `lookup_diagcomms_by_request_prefix` with the full `[SID, DID_HI,
    /// DID_LO]` prefix for direct matching of CODED-CONST DID services.  For
    /// `PhysConst` / Value DID services (where only the SID is a coded constant),
    /// confirms the match via request parameter metadata.
    ///
    /// # Parameters
    /// * `sid` - UDS service identifier (e.g. 0x22 for RDBI, 0x2E for WDBI).
    /// * `did` - 16-bit Data Identifier to resolve.
    /// * `uds_bytes` - Raw incoming UDS request bytes.
    /// * `label` - Log prefix string (e.g. `"READ"`, `"WRITE"`).
    #[allow(clippy::cast_possible_truncation)]
    async fn resolve_service_did(
        &self,
        sid: u8,
        did: u16,
        _uds_bytes: &[u8],
        label: &str,
    ) -> Option<String> {
        let manager = self.manager.read().await;

        // Step 1: Prefix lookup with [SID, DID_HI, DID_LO].
        //
        // The CDA matches sequential coded-const parameters against the prefix:
        // - CODED-CONST DID services -> only exact DID matches pass.
        // - PhysConst / Value DID services -> only the SID byte is coded-const,
        //   so all services with matching SID pass through.
        let did_prefix = [sid, (did >> 8) as u8, (did & 0xFF) as u8];
        let prefix_matches = manager
            .lookup_diagcomms_by_request_prefix(&did_prefix)
            .unwrap_or_default();

        // Fast path: single match from prefix lookup (common case: unique DID).
        if let [only] = prefix_matches.as_slice() {
            let name = only.lookup_name.as_deref().unwrap_or(&only.name);
            tracing::info!(
                "[resolve_did] {} DID 0x{:04X} -> '{}' (prefix match)",
                label,
                did,
                name
            );
            return Some(name.to_owned());
        }

        // Step 2: Build deduplicated candidate list from prefix matches +
        // supplementary sources (bypass NOT-INHERITED-DIAG-COMMS filter).
        let mut seen = std::collections::HashSet::new();
        let mut candidates: Vec<String> = Vec::new();

        for dc in &prefix_matches {
            let name = dc.lookup_name.as_deref().unwrap_or(&dc.name);
            if seen.insert(name.to_owned()) {
                candidates.push(name.to_owned());
            }
        }

        let security_plugin: DynamicPlugin = Box::new(());
        let extra_names: Vec<String> = if sid == service_ids::READ_DATA_BY_IDENTIFIER {
            manager
                .get_components_data_info(&security_plugin)
                .into_iter()
                .map(|c| c.id)
                .collect()
        } else if sid == service_ids::WRITE_DATA_BY_IDENTIFIER {
            manager
                .get_components_configurations_info(&security_plugin)
                .map(|v| v.into_iter().map(|c| c.id).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for name in extra_names {
            if seen.insert(name.clone()) {
                candidates.push(name);
            }
        }

        if candidates.is_empty() {
            tracing::warn!(
                "[resolve_did] {} no services for SID 0x{:02X} DID 0x{:04X}",
                label,
                sid,
                did
            );
            return None;
        }

        tracing::debug!(
            "[resolve_did] {} SID 0x{:02X} DID 0x{:04X}",
            label,
            sid,
            did,
        );

        // Step 3: Match DID against each candidate's request metadata.
        for name in &candidates {
            let Ok(meta) = manager.get_request_parameter_metadata(name) else {
                continue;
            };

            let did_param = find_did_param(&meta, sid);

            let matched = match did_param.map(|p| &p.param_type) {
                Some(cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value }) => {
                    parse_u64_literal(coded_value) == Some(u64::from(did))
                }

                Some(cda_interfaces::ParameterTypeMetadata::PhysConst { coded_value, .. }) => {
                    let resolved = match coded_value {
                        Some(cv) => Some(*cv as u16),
                        None => Self::probe_service_did(&manager, name, sid, &meta).await,
                    };
                    resolved == Some(did)
                }

                Some(cda_interfaces::ParameterTypeMetadata::Value {
                    coded_default_value,
                    compu_scales,
                    ..
                }) => {
                    let default_ok = coded_default_value
                        .map(|cd| cd as u16 == did)
                        .unwrap_or(false);
                    let scales_ok =
                        !compu_scales.is_empty() && did_matches_compu_scales(compu_scales, did);

                    default_ok || scales_ok
                }

                None | Some(cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. }) => {
                    false
                }
            };

            if matched {
                tracing::info!("[resolve_did] {} DID 0x{:04X} -> '{}'", label, did, name);
                return Some(name.clone());
            }
        }

        tracing::error!(
            "[resolve_did] {} no service found for DID 0x{:04X} (checked {} candidates)",
            label,
            did,
            candidates.len()
        );
        None
    }

    /// Find the correct service for a given SID + DID.
    ///
    /// Delegates DID -> service resolution to [`resolve_service_did`] which uses
    /// MDD metadata and probing (`CodedConst`, `PhysConst`, Value+MUX).  Then attempts
    /// parse-validation via `convert_request_from_uds` for the matched service.
    async fn resolve_service(
        &self,
        sid: u8,
        did: u16,
        uds_bytes: &[u8],
        label: &str,
    ) -> Option<(String, serde_json::Map<String, serde_json::Value>)> {
        tracing::debug!("[MDD] {} DID 0x{:04X}", label, did);

        let service_name = self.resolve_service_did(sid, did, uds_bytes, label).await?;

        // Attempt parse-validation to extract structured parameter data.
        let manager = self.manager.read().await;
        let payload = make_service_payload(uds_bytes);
        let diag_comm = DiagComm {
            name: service_name.clone(),
            type_: diag_comm_type(sid),
            lookup_name: Some(service_name.clone()),
        };

        if let Ok(parsed) = manager
            .convert_request_from_uds(&diag_comm, &payload, true)
            .await
            && let Ok(json_resp) = parsed.into_json()
            && let serde_json::Value::Object(map) = json_resp.data
        {
            tracing::debug!(
                "[MDD] {} DID 0x{:04X} -> '{}' (parse verified)",
                label,
                did,
                service_name
            );
            return Some((service_name, map));
        }

        // Parse failed — still return the metadata-resolved service with empty map.
        tracing::debug!(
            "[MDD] {} DID 0x{:04X} -> '{}' (metadata match, parse unavailable)",
            label,
            did,
            service_name
        );
        Some((service_name, serde_json::Map::new()))
    }

    /// Check if a UDS response is negative (SID 0x7F).
    #[must_use]
    pub fn is_negative_response(uds_response: &[u8]) -> bool {
        uds_response.len() >= UDS_NEGATIVE_RESPONSE_MIN_LEN
            && uds_response.first().copied() == Some(service_ids::NEGATIVE_RESPONSE)
    }

    /// Extract NRC (Negative Response Code) from a negative response.
    #[must_use]
    pub fn get_nrc(uds_response: &[u8]) -> Option<u8> {
        if Self::is_negative_response(uds_response) {
            uds_response.get(2).copied()
        } else {
            None
        }
    }

    #[allow(clippy::unused_self)]
    fn make_diag_comm(&self, service_name: &str, service_id: u8) -> DiagComm {
        DiagComm {
            name: service_name.to_string(),
            type_: diag_comm_type(service_id),
            lookup_name: Some(service_name.to_string()),
        }
    }

    /// Get ECU name.
    #[must_use]
    pub fn ecu_name(&self) -> &str {
        &self.ecu_name
    }

    fn default_com_params(logical_address: u16, tester_address: u16) -> ComParams {
        let mut com_params = ComParams::default();
        com_params.doip.logical_gateway_address.default = logical_address;
        com_params.doip.logical_ecu_address.default = logical_address;
        com_params.doip.logical_tester_address.default = tester_address;
        com_params
    }
}

// Helper functions

/// Extract the 16-bit DID from UDS payload bytes at offset 1–2.
///
/// Returns `None` if the slice has fewer than 3 bytes.
fn extract_did_from_uds(data: &[u8]) -> Option<u16> {
    let b1 = *data.get(1)?;
    let b2 = *data.get(2)?;
    Some(u16::from_be_bytes([b1, b2]))
}

/// Map a UDS service identifier to its [`DiagCommType`].
///
/// Falls back to [`DiagCommType::Data`] for unrecognised SIDs so that the
/// caller always receives a usable type rather than an error.
fn diag_comm_type(service_id: u8) -> DiagCommType {
    DiagCommType::try_from(service_id).unwrap_or(DiagCommType::Data)
}

/// Create a `ServicePayload` from raw UDS bytes with default addresses.
fn make_service_payload(data: &[u8]) -> ServicePayload {
    ServicePayload {
        data: data.to_vec(),
        source_address: 0,
        target_address: 0,
        new_session: None,
        new_security: None,
    }
}

/// Encode an unsigned integer as big-endian bytes using the minimum width needed.
///
/// Always produces at least one byte; zero encodes as `[0x00]`.
fn encode_unsigned_be(num: u64) -> Vec<u8> {
    if num == 0 {
        return vec![0x00];
    }
    // Skip leading zero bytes; safe because num != 0 guarantees a non-empty result.
    num.to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect()
}

/// Parse a MUX case `coded_value` string as a numeric DID value.
///
/// MDD stores MUX case limits as strings that may be float-formatted
/// (e.g. `"61699.0"`) or integer-formatted (e.g. `"61699"`).
#[must_use]
pub fn parse_mux_coded_value(coded_value: &str) -> Option<u64> {
    let trimmed = coded_value.trim();
    if let Ok(v) = trimmed.parse::<u64>() {
        return Some(v);
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    if let Ok(v) = trimmed.parse::<f64>()
        && v >= 0.0
        && v <= u64::MAX as f64
    {
        return Some(v as u64);
    }
    None
}

/// Find the MUX case prefix that covers a given DID in response metadata.
///
/// MDD `__mux_case__` entries store only the **`lower_limit`** of their range
/// (e.g. a case with `coded_value: "61697"` covering DIDs 0xF101
/// through 0xF140).  A DID like 0xF103 (61699) has no exact match
/// but falls in that range.
///
/// This function uses **floor-based matching**: collect all `__mux_case__`
/// lower bounds, sort them, and find the case with the largest lower bound
/// that does not exceed the DID.  This correctly handles both single-value
/// MUX cases (e.g. 0x7007) and range cases (e.g. 0xD100–0xD150).
#[must_use]
pub fn find_mux_case_prefix(
    meta: &[cda_interfaces::ResponseParameterInfo],
    did: u16,
) -> Option<String> {
    let did_val = u64::from(did);

    // Collect (lower_bound, case_name) for all MUX case entries.
    let mut mux_entries: Vec<(u64, &str)> = meta
        .iter()
        .filter_map(|p| {
            let case_name = p.name.strip_prefix("__mux_case__/")?;
            if let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
            {
                let lower = parse_mux_coded_value(coded_value)?;
                Some((lower, case_name))
            } else {
                None
            }
        })
        .collect();

    if mux_entries.is_empty() {
        return None;
    }

    // Sort by lower bound ascending.
    mux_entries.sort_by_key(|&(lb, _)| lb);

    // Floor match: largest lower_bound ≤ DID.
    let matched = mux_entries.iter().rev().find(|&&(lb, _)| lb <= did_val)?;

    Some(format!("{}/", matched.1))
}

/// Check if ANY MUX case in the response metadata **exactly** matches the DID.
///
/// Uses exact (not floor) matching because this is for cross-service sibling
/// selection where different MUX DOPs can have overlapping ranges.
#[must_use]
pub fn has_mux_case_for_did_exact(
    meta: &[cda_interfaces::ResponseParameterInfo],
    did: u16,
) -> bool {
    let did_val = u64::from(did);
    meta.iter().any(|p| {
        if let Some(_case_name) = p.name.strip_prefix("__mux_case__/")
            && let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
        {
            return parse_mux_coded_value(coded_value) == Some(did_val);
        }
        false
    })
}

/// Parse numeric literals in decimal or hexadecimal form.
fn parse_u64_literal(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    trimmed
        .parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(trimmed, 16).ok())
}

/// Find the DID-bearing parameter by position and type, not by name.
///
/// In standard UDS requests parameters are stored in byte order:
/// - First `CodedConst` whose value matches the SID -> SID indicator (skip)
/// - Next `CodedConst` / `PhysConst` / `Value` -> DID parameter
///
/// This avoids vendor-specific name or semantic string matching.
fn find_did_param(
    metadata: &[ServiceParameterMetadata],
    sid: u8,
) -> Option<&ServiceParameterMetadata> {
    let mut skipped_sid = false;
    for p in metadata {
        match &p.param_type {
            cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                if !skipped_sid
                    && let Some(val) = parse_u64_literal(coded_value)
                    && val == u64::from(sid)
                {
                    skipped_sid = true;
                    continue;
                }
                // Non-SID CodedConst -> DID param
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::PhysConst { .. }
            | cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                // PhysConst / Value -> DID param
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {}
        }
    }
    None
}

/// Check if a DID falls within any `CompuScale` range from the DOP metadata.
///
/// For TEXTTABLE DOPs each scale defines a coded (internal) DID range.
/// Returns `true` if `did` falls in `[lower_limit, upper_limit]` of any scale.
fn did_matches_compu_scales(scales: &[cda_interfaces::CompuScaleInfo], did: u16) -> bool {
    let did_val = u64::from(did);
    scales.iter().any(|s| match (s.lower_limit, s.upper_limit) {
        (Some(lo), Some(hi)) => did_val >= lo && did_val <= hi,
        (Some(lo), None) => did_val == lo,
        _ => false,
    })
}

/// Encode a JSON value into `buf[pos..pos+size]` using big-endian representation.
///
/// Handles numbers, strings, byte arrays, and booleans.  Fills the entire
/// `size` field, zero-padding on the left for numbers shorter than `size`.
fn encode_value_at(buf: &mut [u8], pos: usize, size: usize, value: Option<&serde_json::Value>) {
    if size == 0 {
        return;
    }
    let Some(end) = pos.checked_add(size) else {
        return;
    };
    if end > buf.len() {
        return;
    }
    let Some(value) = value else {
        // No value provided — leave as zero (already initialised).
        return;
    };
    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            let be = raw.to_be_bytes();
            // Right-align in the field.
            let u64_size = std::mem::size_of::<u64>();
            let start = u64_size.saturating_sub(size);
            let copy = size.min(u64_size);
            // end = pos + size; dst_start = end - copy = pos + (size - copy).
            // copy <= size so no underflow.
            let dst_start = end.saturating_sub(copy);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(dst_start..end),
                be.get(start..start.saturating_add(copy)),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::String(s) => {
            let bytes = s.as_bytes();
            let copy = bytes.len().min(size);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(pos..pos.saturating_add(copy)),
                bytes.get(..copy),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                if i >= size {
                    break;
                }
                if let Some(byte) = item.as_u64()
                    && let Some(slot) = buf.get_mut(pos.saturating_add(i))
                {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *slot = byte as u8;
                    }
                }
            }
        }
        serde_json::Value::Bool(b) => {
            if let Some(slot) = buf.get_mut(pos) {
                *slot = u8::from(*b);
            }
        }
        _ => {}
    }
}

/// Serialize a JSON value into raw bytes for UDS encoding.
///
/// Returns an empty Vec when the value is None or cannot be serialized.
fn value_to_bytes(value: Option<&serde_json::Value>) -> Vec<u8> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            encode_unsigned_be(raw)
        }
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                #[allow(clippy::cast_possible_truncation)]
                item.as_u64().map(|b| b as u8)
            })
            .collect(),
        serde_json::Value::Bool(b) => vec![u8::from(*b)],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_negative_response() {
        assert!(!ServiceResolver::is_negative_response(&[0x62, 0xF1, 0x90]));
        assert!(!ServiceResolver::is_negative_response(&[0x50, 0x01]));
        assert!(ServiceResolver::is_negative_response(&[0x7F, 0x22, 0x31]));
        assert!(!ServiceResolver::is_negative_response(&[0x7F]));
        assert!(!ServiceResolver::is_negative_response(&[0x7F, 0x22]));
    }

    #[test]
    fn test_get_nrc() {
        assert_eq!(ServiceResolver::get_nrc(&[0x62, 0xF1, 0x90]), None);
        assert_eq!(ServiceResolver::get_nrc(&[0x7F, 0x22, 0x31]), Some(0x31));
        assert_eq!(ServiceResolver::get_nrc(&[0x7F, 0x10, 0x11]), Some(0x11));
        assert_eq!(ServiceResolver::get_nrc(&[0x7F, 0x22, 0x22]), Some(0x22));
        assert_eq!(ServiceResolver::get_nrc(&[0x7F]), None);
        assert_eq!(ServiceResolver::get_nrc(&[0x7F, 0x22]), None);
    }

    #[test]
    fn test_nrc_codes() {
        let cases: &[(u8, u8, u8)] = &[
            (0x22, 0x11, 0x11),
            (0x22, 0x12, 0x12),
            (0x22, 0x13, 0x13),
            (0x22, 0x22, 0x22),
            (0x22, 0x31, 0x31),
            (0x27, 0x33, 0x33),
            (0x27, 0x35, 0x35),
            (0x22, 0x78, 0x78),
        ];
        for &(sid, nrc, expected) in cases {
            assert_eq!(ServiceResolver::get_nrc(&[0x7F, sid, nrc]), Some(expected));
        }
    }

    #[test]
    fn test_positive_response_sids() {
        assert!(!ServiceResolver::is_negative_response(&[
            0x50, 0x01, 0x00, 0x32
        ]));
        assert!(!ServiceResolver::is_negative_response(&[
            0x62, 0xF1, 0x90, 0x57
        ]));
        assert!(!ServiceResolver::is_negative_response(&[
            0x67, 0x01, 0x12, 0x34
        ]));
        assert!(!ServiceResolver::is_negative_response(&[0x6E, 0xF1, 0x90]));
        assert!(!ServiceResolver::is_negative_response(&[0x7E, 0x00]));
    }

    #[test]
    fn test_default_com_params() {
        let com_params = ServiceResolver::default_com_params(0x1000, 0x0E80);
        assert_eq!(com_params.doip.logical_gateway_address.default, 0x1000);
        assert_eq!(com_params.doip.logical_ecu_address.default, 0x1000);
        assert_eq!(com_params.doip.logical_tester_address.default, 0x0E80);
        assert_eq!(
            com_params.doip.logical_gateway_address.name,
            "CP_DoIPLogicalGatewayAddress"
        );
        assert_eq!(
            com_params.doip.logical_ecu_address.name,
            "CP_DoIPLogicalEcuAddress"
        );
        assert_eq!(
            com_params.doip.logical_response_id_table_name,
            "CP_UniqueRespIdTable"
        );
    }

    #[test]
    fn test_diag_comm_type() {
        assert!(matches!(
            diag_comm_type(service_ids::WRITE_DATA_BY_IDENTIFIER),
            DiagCommType::Configurations
        ));
        assert!(matches!(
            diag_comm_type(service_ids::READ_DATA_BY_IDENTIFIER),
            DiagCommType::Data
        ));
        assert!(matches!(
            diag_comm_type(service_ids::SESSION_CONTROL),
            DiagCommType::Modes
        ));
        assert!(matches!(
            diag_comm_type(service_ids::TESTER_PRESENT),
            DiagCommType::Data
        ));
        assert!(matches!(
            diag_comm_type(service_ids::ROUTINE_CONTROL),
            DiagCommType::Operations
        ));
        assert!(matches!(
            diag_comm_type(service_ids::CLEAR_DIAGNOSTIC_INFORMATION),
            DiagCommType::Faults
        ));
    }

    #[test]
    fn test_encode_unsigned_be() {
        assert_eq!(encode_unsigned_be(0), vec![0x00]);
        assert_eq!(encode_unsigned_be(0xFF), vec![0xFF]);
        assert_eq!(encode_unsigned_be(0x0100), vec![0x01, 0x00]);
        assert_eq!(encode_unsigned_be(0xF190), vec![0xF1, 0x90]);
        assert_eq!(encode_unsigned_be(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_unsigned_be(0x01_0000), vec![0x01, 0x00, 0x00]);
        assert_eq!(encode_unsigned_be(0xFF_FFFF), vec![0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encode_unsigned_be(0x0100_0000),
            vec![0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_unsigned_be(0xDEAD_BEEF),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_make_service_payload() {
        let data = &[0x62, 0xF1, 0x90, 0x57];
        let payload = make_service_payload(data);
        assert_eq!(payload.data, vec![0x62, 0xF1, 0x90, 0x57]);
        assert_eq!(payload.source_address, 0);
        assert_eq!(payload.target_address, 0);
        assert!(payload.new_session.is_none());
        assert!(payload.new_security.is_none());
    }

    #[test]
    fn test_empty_response() {
        assert!(!ServiceResolver::is_negative_response(&[]));
        assert_eq!(ServiceResolver::get_nrc(&[]), None);
    }

    #[test]
    fn test_find_did_param() {
        use cda_interfaces::ParameterTypeMetadata;

        // Standard RDBI: CodedConst SID + PhysConst DID
        let meta = vec![
            ServiceParameterMetadata {
                name: "RDBI".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(), // 0x22
                },
            },
            ServiceParameterMetadata {
                name: "VIN".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::PhysConst {
                    phys_constant_value: "VIN".to_string(),
                    coded_value: Some(0xF190),
                },
            },
        ];
        let did = find_did_param(&meta, 0x22);
        assert!(did.is_some());
        assert_eq!(did.expect("DID param not found").name, "VIN");

        // Value-type service: SID + Value DID
        let meta2 = vec![
            ServiceParameterMetadata {
                name: "SID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(),
                },
            },
            ServiceParameterMetadata {
                name: "DynamicDID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
            },
        ];
        let did = find_did_param(&meta2, 0x22);
        assert!(did.is_some());
        assert!(matches!(
            did.expect("DID param not found").param_type,
            ParameterTypeMetadata::Value { .. }
        ));

        // SID-only service: no DID param
        let meta3 = vec![ServiceParameterMetadata {
            name: "SID".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: "34".to_string(),
            },
        }];
        assert!(find_did_param(&meta3, 0x22).is_none());
    }

    #[test]
    fn test_parse_mux_coded_value() {
        assert_eq!(parse_mux_coded_value("61699"), Some(61699));
        assert_eq!(parse_mux_coded_value("32776"), Some(32776));
        assert_eq!(parse_mux_coded_value("61699.0"), Some(61699));
        assert_eq!(parse_mux_coded_value(" 61699 "), Some(61699));
        assert_eq!(parse_mux_coded_value("non_numeric_text"), None);
        assert_eq!(parse_mux_coded_value(""), None);
    }

    #[test]
    fn test_find_mux_case_prefix_floor_match() {
        use cda_interfaces::{ParameterTypeMetadata, ResponseParameterInfo};

        // Simulate real RDBI_RESP metadata with range-based and point MUX cases.
        let meta = vec![
            // Point case: DID_POINT_8008 covers only DID 0x8008 (32776)
            ResponseParameterInfo {
                name: "__mux_case__/DID_POINT_8008".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "32776".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            // Range case: DID_RANGE_F101_F140 covers 0xF101 (61697) through 0xF140 (61760)
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
            // Point case: DID_POINT_F141 covers only 0xF141 (61761)
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
        ];

        // Exact match
        assert_eq!(
            find_mux_case_prefix(&meta, 0x8008),
            Some("DID_POINT_8008/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF101),
            Some("DID_RANGE_F101_F140/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF141),
            Some("DID_POINT_F141/".to_string())
        );

        // Floor match within range
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF103), // 61699 -> floor to 61697
            Some("DID_RANGE_F101_F140/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF140), // 61760 -> floor to 61697
            Some("DID_RANGE_F101_F140/".to_string())
        );

        // Float-formatted coded_value
        let meta_float = vec![ResponseParameterInfo {
            name: "__mux_case__/case_a".to_string(),
            semantic: Some("MUX-CASE".to_string()),
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: "61697.0".to_string(),
            },
            byte_position: 3,
            bit_position: 0,
            byte_size: None,
        }];
        assert_eq!(
            find_mux_case_prefix(&meta_float, 0xF103),
            Some("case_a/".to_string())
        );

        // No MUX entries -> None
        assert_eq!(find_mux_case_prefix(&[], 0xF103), None);
    }
}
