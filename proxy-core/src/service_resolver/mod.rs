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
//! ## Module layout
//!
//! - [`uds_helpers`]: Pure helper functions for UDS encoding, decoding, MUX
//!   matching, and payload construction.
//! - [`response`]: UDS response building and round-trip validation.
//! - [`metadata`]: Service metadata queries and MUX-sibling enrichment.
//! - [`resolve`]: DID-to-service resolution, request parsing, and probing.
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

mod metadata;
mod resolve;
mod response;
pub mod uds_helpers;

use std::sync::Arc;

use cda_core::{DiagServiceResponseStruct, EcuManager as CdaEcuManager};
use cda_database::datatypes::DiagnosticDatabase;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, EcuManager as EcuManagerTrait, EcuManagerType,
    FunctionalDescriptionConfig, HashMap, Protocol,
    datatypes::{ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition},
    diagservices::DiagServiceResponseType,
};
use cda_plugin_security::DefaultSecurityPluginData;
use tokio::sync::RwLock;
pub use uds_helpers::{
    UdsResponse, find_mux_case_prefix, has_mux_case_for_did_exact, parse_mux_coded_value,
};

/// Minimum UDS negative response length: 0x7F + SID + NRC.
const UDS_NEGATIVE_RESPONSE_MIN_LEN: usize = 3;

/// Minimum UDS positive response buffer size: response SID (1) + DID high (1) + DID low (1).
const UDS_POSITIVE_RESPONSE_MIN_SIZE: usize = 3;

/// Result of a successful UDS DID-to-service resolution.
pub struct ResolvedService {
    /// The matched MDD service name (e.g. `"RDBI_VIN"`).
    pub name: String,
    /// Decoded request parameters as a JSON map.
    ///
    /// Empty when the CDA request parser is unavailable for the matched service.
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// Wraps the CDA's [`EcuManager`] with async locking
/// to provide MDD-driven UDS encoding, decoding, and service resolution
#[derive(Clone)]
pub struct ServiceResolver {
    /// All post-construction access uses `.read()` for concurrent reads.
    /// The write lock is reserved for future runtime variant detection
    /// (`detect_variant` requires `&mut CdaEcuManager`).
    manager: Arc<RwLock<CdaEcuManager<DefaultSecurityPluginData>>>,
    ecu_name: String,
}

impl ServiceResolver {
    /// Create new service resolver from ECU name and MDD database.
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
    /// <https://github.com/eclipse-opensovd/uds2sovd-proxy/issues/16>
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

        manager
            .detect_variant(responses)
            .await
            .or_else(|e| match manager.variant().name {
                Some(ref name) => {
                    tracing::info!(
                        "Base variant '{}' activated (state chart init skipped: {})",
                        name,
                        e
                    );
                    Ok(())
                }
                None => Err(e),
            })
    }

    /// Check if a UDS response is negative (SID 0x7F).
    #[must_use]
    pub fn is_negative_response(uds_response: &[u8]) -> bool {
        UdsResponse::new(uds_response).is_negative()
    }

    /// Extract NRC (Negative Response Code) from a negative response.
    #[must_use]
    pub fn get_nrc(uds_response: &[u8]) -> Option<u8> {
        UdsResponse::new(uds_response).nrc()
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
    fn test_empty_response() {
        assert!(!ServiceResolver::is_negative_response(&[]));
        assert_eq!(ServiceResolver::get_nrc(&[]), None);
    }
}
