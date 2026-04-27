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

//! Service metadata queries and lookup.
//!
//! Methods for querying request/response parameter metadata from the MDD,
//! looking up services by SID, and retrieving MUX case information.

use cda_interfaces::{
    DiagServiceError, DynamicPlugin, EcuManager as EcuManagerTrait, MuxCaseInfo,
    ServiceParameterMetadata, service_ids,
};

use super::{ServiceResolver, uds_helpers::has_mux_case_for_did_exact};

impl ServiceResolver {
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

    /// Lookup all service names for a given UDS service ID (SID).
    ///
    /// Returns READ services for SID 0x22, WRITE services for SID 0x2E,
    /// or an empty vector for unrecognized SIDs.
    ///
    /// # Errors
    /// Does not currently return errors; always succeeds with a Vec<String>.
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

    /// Retrieve MUX case definitions for a given service.
    ///
    /// Queries the MDD for all MUX cases associated with the service,
    /// used to determine which parameters are active for each MUX value.
    ///
    /// # Errors
    /// Returns an error if the service is not found or MDD query fails.
    pub async fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<MuxCaseInfo>, DiagServiceError> {
        let manager = self.manager.read().await;
        manager.get_mux_cases_for_service(service_name)
    }

    /// Retrieve enriched POS-RESPONSE metadata with source service name.
    ///
    /// Same as [`MetadataQuerying::get_enriched_response_metadata`] but also returns
    /// the name of the service that actually provided the metadata. When the response is
    /// "opaque" (single STRUCTURE ref) and a MUX-based sibling is used, the
    /// returned name is the sibling — callers that need to validate via
    /// `convert_from_uds` must use this name, not the original.
    ///
    /// # Errors
    /// Returns an error if the metadata is not available.
    pub(super) async fn get_enriched_response_metadata_with_source(
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
        for component in manager.get_components_data_info(&security_plugin) {
            let candidate = component.id;
            if candidate == service_name {
                continue;
            }
            let sibling_meta = match manager.get_response_parameter_metadata(&candidate) {
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
                return Ok((sibling_meta, candidate));
            }
        }

        // No MUX sibling found — use original metadata.
        Ok((meta, service_name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{ParameterTypeMetadata, ResponseParameterInfo};

    use super::super::uds_helpers::{find_mux_case_prefix, has_mux_case_for_did_exact};

    /// Build a minimal `ResponseParameterInfo` MUX-case entry for test fixtures.
    fn mux_case(name: &str, coded_lower: u64) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: format!("__mux_case__/{name}"),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: coded_lower.to_string(),
            },
            byte_position: 0,
            bit_position: 0,
            byte_size: None,
        }
    }

    /// Build a plain VALUE parameter at a given byte position.
    fn value_param(name: &str, pos: u32, size: u32) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::Value {
                physical_default_value: None,
                coded_default_value: None,
                compu_scales: vec![],
            },
            byte_position: pos,
            bit_position: 0,
            byte_size: Some(size),
        }
    }

    #[test]
    fn test_has_mux_exact_match() {
        let meta = vec![mux_case("VIN", 0xF190)];
        assert!(has_mux_case_for_did_exact(&meta, 0xF190));
    }

    #[test]
    fn test_has_mux_exact_no_match() {
        let meta = vec![mux_case("VIN", 0xF190)];
        // 0xF191 is one beyond the only entry — no match.
        assert!(!has_mux_case_for_did_exact(&meta, 0xF191));
    }

    #[test]
    fn test_has_mux_exact_vs_floor_semantics() {
        // Floor matching (find_mux_case_prefix) would return the 0xF100 case for
        // 0xF103, but has_mux_case_for_did_exact must NOT.
        let meta = vec![mux_case("RANGE", 0xF100)];
        assert!(!has_mux_case_for_did_exact(&meta, 0xF103));
        // Only the exact value matches.
        assert!(has_mux_case_for_did_exact(&meta, 0xF100));
    }

    #[test]
    fn test_has_mux_exact_empty_meta() {
        assert!(!has_mux_case_for_did_exact(&[], 0xF190));
    }

    #[test]
    fn test_has_mux_exact_non_mux_params_ignored() {
        let meta = vec![value_param("DATA", 3, 17)];
        assert!(!has_mux_case_for_did_exact(&meta, 0x0000));
    }

    #[test]
    fn test_floor_vs_exact_differ_for_range_case() {
        let meta = vec![mux_case("RANGE", 0xF100), mux_case("OTHER", 0xF200)];
        // Floor: 0xF103 falls in the 0xF100 range → prefix returned.
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF103),
            Some("RANGE/".to_string())
        );
        // Exact: 0xF103 has no exact entry → false.
        assert!(!has_mux_case_for_did_exact(&meta, 0xF103));
        // But 0xF100 itself is an exact hit.
        assert!(has_mux_case_for_did_exact(&meta, 0xF100));
    }

    // The heuristic inside `get_enriched_response_metadata_with_source` checks:
    //   is_opaque = data_params.len() == 1 && first.byte_size.is_none() &&
    //                !first.name.contains('/')
    // We test the data-model conditions that drive it directly.

    #[test]
    fn test_opaque_heuristic_single_none_size_param() {
        // Only one VALUE param with byte_size = None and no '/' in name → opaque.
        let param = ResponseParameterInfo {
            name: "STRUCTURE_DATA".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::Value {
                physical_default_value: None,
                coded_default_value: None,
                compu_scales: vec![],
            },
            byte_position: 3,
            bit_position: 0,
            byte_size: None,
        };
        let data_params: Vec<_> = std::slice::from_ref(&param)
            .iter()
            .filter(|p| {
                matches!(
                    p.param_type,
                    ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();

        let first = data_params.first().unwrap();
        let is_opaque =
            data_params.len() == 1 && first.byte_size.is_none() && !first.name.contains('/');
        assert!(is_opaque);
    }

    #[test]
    fn test_opaque_heuristic_sized_param_not_opaque() {
        // A VALUE param WITH a byte_size is NOT opaque (it has a known layout).
        let param = value_param("DATA", 3, 17);
        let data_params: Vec<_> = std::slice::from_ref(&param)
            .iter()
            .filter(|p| {
                matches!(
                    p.param_type,
                    ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();
        let first = data_params.first().unwrap();
        let is_opaque =
            data_params.len() == 1 && first.byte_size.is_none() && !first.name.contains('/');
        assert!(!is_opaque);
    }

    #[test]
    fn test_opaque_heuristic_mux_subparam_not_opaque() {
        // A MUX sub-param has '/' in its name → not opaque even if byte_size is None.
        let param = ResponseParameterInfo {
            name: "__mux_case__/VIN/DATA".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::Value {
                physical_default_value: None,
                coded_default_value: None,
                compu_scales: vec![],
            },
            byte_position: 3,
            bit_position: 0,
            byte_size: None,
        };
        let data_params: Vec<_> = std::slice::from_ref(&param)
            .iter()
            .filter(|p| {
                matches!(
                    p.param_type,
                    ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();
        let first = data_params.first().unwrap();
        let is_opaque =
            data_params.len() == 1 && first.byte_size.is_none() && !first.name.contains('/');
        assert!(!is_opaque);
    }

    #[test]
    fn test_opaque_heuristic_multiple_params_not_opaque() {
        // Multiple VALUE params → structured layout, NOT opaque.
        let params = vec![value_param("FIELD_A", 3, 2), value_param("FIELD_B", 5, 1)];
        let data_params: Vec<_> = params
            .iter()
            .filter(|p| {
                matches!(
                    p.param_type,
                    ParameterTypeMetadata::Value { .. } | ParameterTypeMetadata::PhysConst { .. }
                )
            })
            .collect();
        let first = data_params.first().unwrap();
        let is_opaque =
            data_params.len() == 1 && first.byte_size.is_none() && !first.name.contains('/');
        assert!(!is_opaque);
    }
}
