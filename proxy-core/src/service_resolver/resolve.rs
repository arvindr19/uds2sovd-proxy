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

//! DID-to-service resolution logic.
//!
//! Resolves incoming UDS DID values to the correct MDD service name
//! using prefix lookup, request parameter metadata, and encoding probes.
//!
//! # Exported Methods (via `ServiceResolver`)
//! - [`ServiceResolver::resolve_read_service`]: Resolve READ service for DID
//! - [`ServiceResolver::resolve_write_service`]: Resolve WRITE service for DID
//!
//! # Algorithm Overview
//! 1. `Prefix lookup` via `[SID, DID_HI, DID_LO]` against MDD coded-const services
//! 2. `Fast path`: Single prefix match -> return immediately
//! 3. `Candidate enumeration`: SID-matching services + component data/config
//! 4. `Metadata matching`: `CodedConst` (exact), `PhysConst` (`coded_value` or probe),
//!    `Value` (range/list via `CompuScale`)
//! 5. `Parse validation`: Attempt CDA `convert_request_from_uds` to extract params

use cda_core::EcuManager as CdaEcuManager;
use cda_interfaces::{
    DynamicPlugin, EcuManager as EcuManagerTrait, HashMap, ServiceParameterMetadata,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    service_ids,
};
use cda_plugin_security::DefaultSecurityPluginData;

use super::{
    ResolvedService, ServiceResolver,
    uds_helpers::{
        did_matches_compu_scales, extract_did_from_uds, find_did_param, make_diag_comm,
        make_service_payload, parse_u64_literal,
    },
};

impl ServiceResolver {
    /// Resolve the best-matching READ service for UDS request bytes.
    pub async fn resolve_read_service(
        &self,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<ResolvedService> {
        self.resolve_service(service_ids::READ_DATA_BY_IDENTIFIER, did, uds_bytes, "READ")
            .await
    }

    /// Resolve the best-matching WRITE service for UDS request bytes.
    pub async fn resolve_write_service(
        &self,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<ResolvedService> {
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

        let diag_comm = make_diag_comm(service_name, sid);
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

        // Step 1 + 2: prefix lookup and candidate list construction.
        let did_prefix = [sid, (did >> 8) as u8, (did & 0xFF) as u8];
        let candidates = Self::build_did_candidates(&manager, did_prefix, sid, did, label)?;

        // Step 3: match DID against each candidate's request metadata.
        for name in &candidates {
            if self.match_candidate_did(&manager, name, sid, did).await {
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

    /// Step 1 + 2: prefix lookup, fast-path, and candidate list.
    ///
    /// Returns `None` (after logging) when no candidates exist.
    /// Returns `Some` with a single name already when the fast path fires
    /// (only one prefix match — skip Step 3 entirely).
    fn build_did_candidates(
        manager: &CdaEcuManager<DefaultSecurityPluginData>,
        did_prefix: [u8; 3],
        sid: u8,
        did: u16,
        label: &str,
    ) -> Option<Vec<String>> {
        // Step 1: Prefix lookup with [SID, DID_HI, DID_LO].
        //
        // The CDA matches sequential coded-const parameters against the prefix:
        // - CODED-CONST DID services -> only exact DID matches pass.
        // - PhysConst / Value DID services -> only the SID byte is coded-const,
        //   so all services with matching SID pass through.
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
            return Some(vec![name.to_owned()]);
        }

        // Step 2: Build deduplicated candidate list from prefix matches +
        // supplementary sources (bypass NOT-INHERITED-DIAG-COMMS filter).
        let mut candidates: Vec<String> = Vec::new();

        for dc in &prefix_matches {
            let name = dc.lookup_name.as_deref().unwrap_or(&dc.name).to_owned();
            if !candidates.contains(&name) {
                candidates.push(name);
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
            if !candidates.contains(&name) {
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
            "[resolve_did] {} SID 0x{:02X} DID 0x{:04X} ({} candidates)",
            label,
            sid,
            did,
            candidates.len(),
        );

        Some(candidates)
    }

    /// Step 3: check if `candidate_name` matches `did` via request parameter metadata.
    #[allow(clippy::cast_possible_truncation)]
    async fn match_candidate_did(
        &self,
        manager: &CdaEcuManager<DefaultSecurityPluginData>,
        candidate_name: &str,
        sid: u8,
        did: u16,
    ) -> bool {
        let Ok(meta) = manager.get_request_parameter_metadata(candidate_name) else {
            return false;
        };

        let did_param = find_did_param(&meta, sid);

        match did_param.map(|p| &p.param_type) {
            Some(cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value }) => {
                parse_u64_literal(coded_value) == Some(u64::from(did))
            }

            Some(cda_interfaces::ParameterTypeMetadata::PhysConst { coded_value, .. }) => {
                #[allow(clippy::cast_possible_truncation)]
                let resolved = match coded_value {
                    Some(cv) => Some(*cv as u16),
                    None => Self::probe_service_did(manager, candidate_name, sid, &meta).await,
                };
                resolved == Some(did)
            }

            Some(cda_interfaces::ParameterTypeMetadata::Value {
                coded_default_value,
                compu_scales,
                ..
            }) => {
                #[allow(clippy::cast_possible_truncation)]
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
        }
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
    ) -> Option<ResolvedService> {
        tracing::debug!("[MDD] {} DID 0x{:04X}", label, did);

        let service_name = self.resolve_service_did(sid, did, uds_bytes, label).await?;

        // Attempt parse-validation to extract structured parameter data.
        let manager = self.manager.read().await;
        let payload = make_service_payload(uds_bytes);
        let diag_comm = make_diag_comm(&service_name, sid);

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
            return Some(ResolvedService {
                name: service_name,
                params: map,
            });
        }

        // Parse failed — still return the metadata-resolved service with empty map.
        tracing::debug!(
            "[MDD] {} DID 0x{:04X} -> '{}' (metadata match, parse unavailable)",
            label,
            did,
            service_name
        );
        Some(ResolvedService {
            name: service_name,
            params: serde_json::Map::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::service_ids;

    use super::super::uds_helpers::{did_matches_compu_scales, find_did_param, parse_u64_literal};

    /// `parse_u64_literal` parses decimal and hexadecimal strings.
    #[test]
    fn test_parse_u64_literal_decimal() {
        assert_eq!(parse_u64_literal("0"), Some(0));
        assert_eq!(parse_u64_literal("61699"), Some(61_699));
    }

    #[test]
    fn test_parse_u64_literal_hex() {
        assert_eq!(parse_u64_literal("0xF103"), Some(0xF103));
        assert_eq!(parse_u64_literal("0XFF"), Some(0xFF));
        // bare hex fallback (no prefix)
        assert_eq!(parse_u64_literal("F103"), Some(0xF103));
    }

    #[test]
    fn test_parse_u64_literal_invalid() {
        assert_eq!(parse_u64_literal(""), None);
        assert_eq!(parse_u64_literal("abc xyz"), None);
    }

    /// `did_matches_compu_scales` returns true when DID falls in any range.
    #[test]
    fn test_did_matches_compu_scales_in_range() {
        use cda_interfaces::CompuScaleInfo;
        let scales = vec![CompuScaleInfo {
            short_label: None,
            lower_limit: Some(0xF100),
            upper_limit: Some(0xF1FF),
            compu_const_vt: None,
        }];
        assert!(did_matches_compu_scales(&scales, 0xF190));
        assert!(did_matches_compu_scales(&scales, 0xF100));
        assert!(did_matches_compu_scales(&scales, 0xF1FF));
        assert!(!did_matches_compu_scales(&scales, 0xF200));
    }

    /// `find_did_param` skips the SID `CodedConst` and returns the next parameter.
    #[test]
    fn test_find_did_param_skips_sid() {
        use cda_interfaces::{ParameterTypeMetadata, ServiceParameterMetadata};
        let sid = service_ids::READ_DATA_BY_IDENTIFIER; // 0x22
        let meta = vec![
            ServiceParameterMetadata {
                name: "SID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(), // 0x22
                },
            },
            ServiceParameterMetadata {
                name: "DID".to_string(),
                semantic: Some("DATA-IDENTIFIER".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61824".to_string(), // 0xF190
                },
            },
        ];
        let param = find_did_param(&meta, sid);
        assert!(param.is_some());
        assert_eq!(param.unwrap().name, "DID");
    }

    /// `find_did_param` returns `None` when no DID parameter is present.
    #[test]
    fn test_find_did_param_none_when_only_sid() {
        use cda_interfaces::{ParameterTypeMetadata, ServiceParameterMetadata};
        let sid = service_ids::READ_DATA_BY_IDENTIFIER;
        let meta = vec![ServiceParameterMetadata {
            name: "SID".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: "34".to_string(),
            },
        }];
        assert!(find_did_param(&meta, sid).is_none());
    }
}
