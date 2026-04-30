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
//! Resolves incoming UDS DID values to the correct MDD service name
//! using prefix lookup, request parameter metadata, and encoding probes.

use cda_core::EcuManager as CdaEcuManager;
use cda_interfaces::{
    DynamicPlugin, EcuManager as EcuManagerTrait, HashMap, ServiceParameterMetadata,
    diagservices::{DiagServiceResponse, UdsPayloadData},
};
use cda_plugin_security::DefaultSecurityPluginData;

use super::{
    ManagerHandle,
    uds_helpers::{
        did_matches_compu_scales, extract_did_from_uds, find_did_param, make_diag_comm,
        make_service_payload, parse_u64_literal,
    },
    uds_service_ids,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// `ReadDataByIdentifier` (SID 0x22).
    Read,
    /// `WriteDataByIdentifier` (SID 0x2E).
    Write,
}

impl ServiceType {
    /// UDS service identifier byte.
    #[must_use]
    pub fn sid(self) -> u8 {
        match self {
            Self::Read => uds_service_ids::READ_DATA_BY_IDENTIFIER,
            Self::Write => uds_service_ids::WRITE_DATA_BY_IDENTIFIER,
        }
    }

    /// Human-readable label for log messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

/// Successful result of DID-to-service resolution.
pub struct ResolvedService {
    /// Matched MDD service name (e.g. `"RDBI_VIN"`).
    pub name: String,
    /// Decoded request parameters, or an empty map when the CDA parser
    /// is unavailable for the matched service.
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// Resolves UDS DID values to MDD service names.
pub struct DidResolver {
    manager: ManagerHandle,
}

impl DidResolver {
    /// Create a new resolver backed by the given manager handle.
    pub fn new(manager: ManagerHandle) -> Self {
        Self { manager }
    }

    /// Resolve the best-matching service for a UDS DID request.
    pub async fn resolve(
        &self,
        service_type: ServiceType,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<ResolvedService> {
        let sid = service_type.sid();
        let label = service_type.label();
        tracing::debug!("[MDD] {} DID 0x{:04X}", label, did);

        let service_name = self.resolve_service_did(sid, did, label).await?;

        // Attempt parse-validation to extract structured parameter data.
        let manager = self.manager.read().await;
        let payload: cda_interfaces::ServicePayload = make_service_payload(uds_bytes);
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

        // Parse failed -- still return the metadata-resolved service with empty map.
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

    /// Resolve a DID to a service name using prefix lookup and metadata.
    ///
    /// Step 1: prefix lookup with `[SID, DID_HI, DID_LO]`.
    /// Step 2: build candidate list.
    /// Step 3: match each candidate via request parameter metadata.
    // `did` is `u16`; `did >> 8` is at most 0xFF and `did & 0xFF` is at most 0xFF,
    // so both narrowing casts to `u8` are safe and can never truncate.
    #[allow(clippy::cast_possible_truncation)]
    async fn resolve_service_did(&self, sid: u8, did: u16, label: &str) -> Option<String> {
        let manager = self.manager.read().await;

        // Step 1 + 2: prefix lookup and candidate list construction.
        let did_prefix = [sid, (did >> 8) as u8, (did & 0xFF) as u8];
        let candidates = Self::build_did_candidates(&manager, did_prefix, sid, did, label)?;

        // Step 3: match DID against each candidate's request metadata.
        for name in &candidates {
            if Self::match_candidate_did(&manager, name, sid, did).await {
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

    /// Build the candidate list from prefix lookup and supplementary sources.
    ///
    /// Returns `Some` with a single-element vec on a unique prefix match
    /// (fast path). Returns `None` when no candidates exist.
    fn build_did_candidates(
        manager: &CdaEcuManager<DefaultSecurityPluginData>,
        did_prefix: [u8; 3],
        sid: u8,
        did: u16,
        label: &str,
    ) -> Option<Vec<String>> {
        // Prefix lookup with [SID, DID_HI, DID_LO].
        // CODED-CONST DID services only pass on exact DID match;
        // PhysConst/Value services pass when the SID byte matches.
        let prefix_matches = manager
            .lookup_diagcomms_by_request_prefix(&did_prefix)
            .unwrap_or_default();

        // Single prefix match (common case: unique DID) -- skip metadata check.
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

        // Build deduplicated candidate list from prefix matches and
        // supplementary sources (bypasses NOT-INHERITED-DIAG-COMMS filter).
        let mut candidates: Vec<String> = Vec::new();

        for dc in &prefix_matches {
            let name = dc.lookup_name.as_deref().unwrap_or(&dc.name).to_owned();
            if !candidates.contains(&name) {
                candidates.push(name);
            }
        }

        let security_plugin: DynamicPlugin = Box::new(());
        let extra_names: Vec<String> = if sid == uds_service_ids::READ_DATA_BY_IDENTIFIER {
            manager
                .get_components_data_info(&security_plugin)
                .into_iter()
                .map(|c| c.id)
                .collect()
        } else if sid == uds_service_ids::WRITE_DATA_BY_IDENTIFIER {
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

    /// Check if `candidate_name` matches `did` via request parameter metadata.
    async fn match_candidate_did(
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
                // f64 -> u16 narrowing is safe for DID range (0x0000-0xFFFF).
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
                // f64 -> u16 narrowing is safe for DID range.
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
        // ISO 14229-1: DID 0x0000 is reserved; treat zero as unresolvable.
        if probed_did == 0 {
            None
        } else {
            Some(probed_did)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        uds_helpers::{did_matches_compu_scales, find_did_param, parse_u64_literal},
        uds_service_ids,
    };
    #[test]
    fn test_parse_u64_literal_decimal() {
        assert_eq!(parse_u64_literal("0"), Some(0));
        assert_eq!(parse_u64_literal("61699"), Some(61_699));
    }

    #[test]
    fn test_parse_u64_literal_hex() {
        assert_eq!(parse_u64_literal("0xF103"), Some(0xF103));
        assert_eq!(parse_u64_literal("0XFF"), Some(0xFF));
        assert_eq!(parse_u64_literal("F103"), Some(0xF103));
    }

    #[test]
    fn test_parse_u64_literal_invalid() {
        assert_eq!(parse_u64_literal(""), None);
        assert_eq!(parse_u64_literal("abc xyz"), None);
    }

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

    #[test]
    fn test_find_did_param_skips_sid() {
        use cda_interfaces::{ParameterTypeMetadata, ServiceParameterMetadata};
        let sid = uds_service_ids::READ_DATA_BY_IDENTIFIER;
        let meta = vec![
            ServiceParameterMetadata {
                name: "SID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(),
                },
            },
            ServiceParameterMetadata {
                name: "DID".to_string(),
                semantic: Some("DATA-IDENTIFIER".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61824".to_string(),
                },
            },
        ];
        let did_param = find_did_param(&meta, sid);
        assert!(did_param.is_some());
        assert_eq!(did_param.unwrap().name, "DID");
    }

    #[test]
    fn test_service_type_sid() {
        assert_eq!(super::ServiceType::Read.sid(), 0x22);
        assert_eq!(super::ServiceType::Write.sid(), 0x2E);
    }

    #[test]
    fn test_service_type_label() {
        assert_eq!(super::ServiceType::Read.label(), "READ");
        assert_eq!(super::ServiceType::Write.label(), "WRITE");
    }

    #[test]
    fn test_find_did_param_phys_const() {
        use cda_interfaces::{ParameterTypeMetadata, ServiceParameterMetadata};
        let sid = uds_service_ids::READ_DATA_BY_IDENTIFIER;
        let meta = vec![
            ServiceParameterMetadata {
                name: "SID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(),
                },
            },
            ServiceParameterMetadata {
                name: "DID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::PhysConst {
                    phys_constant_value: "VIN".to_string(),
                    coded_value: Some(0xF190),
                },
            },
        ];
        let did_param = find_did_param(&meta, sid);
        assert!(did_param.is_some());
        assert_eq!(did_param.unwrap().name, "DID");
    }

    #[test]
    fn test_find_did_param_no_sid_match() {
        use cda_interfaces::{ParameterTypeMetadata, ServiceParameterMetadata};
        let meta = vec![ServiceParameterMetadata {
            name: "ONLY_PARAM".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::PhysConst {
                phys_constant_value: "VALUE".to_string(),
                coded_value: None,
            },
        }];
        let did_param = find_did_param(&meta, 0x22);
        assert!(did_param.is_some());
        assert_eq!(did_param.unwrap().name, "ONLY_PARAM");
    }

    #[test]
    fn test_find_did_param_empty_metadata() {
        let meta: Vec<cda_interfaces::ServiceParameterMetadata> = vec![];
        assert!(find_did_param(&meta, 0x22).is_none());
    }
}
