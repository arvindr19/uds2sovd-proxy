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

//! DID-to-service resolution.
//!
//! Resolves incoming UDS DID values to the correct MDD service name using
//! prefix lookup, request parameter metadata, and encoding probes.

use cda_core::EcuManager as CdaEcuManager;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuManager as EcuManagerTrait, HashMap,
    ServiceParameterMetadata,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    service_ids,
};
use cda_plugin_security::DefaultSecurityPluginData;

use super::{
    ServiceResolver,
    uds_helpers::{
        diag_comm_type, did_matches_compu_scales, extract_did_from_uds, find_did_param,
        make_service_payload, parse_u64_literal,
    },
};

impl ServiceResolver {
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
}
