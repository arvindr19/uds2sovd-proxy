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

    /// Same as [`get_enriched_response_metadata`] but also returns the name of
    /// the service that actually provided the metadata. When the response is
    /// "opaque" (single STRUCTURE ref) and a MUX-based sibling is used, the
    /// returned name is the sibling — callers that need to validate via
    /// `convert_from_uds` must use this name, not the original.
    ///
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
}
