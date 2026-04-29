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

//! MDD-driven UDS encoding, decoding, and service resolution.
//!
//! `ServiceResolver` is a thin facade that owns the CDA `EcuManager` and
//! exposes three focused sub-components via accessor methods:
//!
//! - [`DidResolver`] -- DID-to-service resolution
//! - [`ResponseEncoder`] -- UDS response encoding
//! - [`MetadataProvider`] -- MDD parameter queries

mod metadata;
mod resolve;
mod response;
pub mod uds_helpers;

use std::sync::Arc;

use cda_core::{DiagServiceResponseStruct, EcuManager};
use cda_database::datatypes::DiagnosticDatabase;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, EcuManager as EcuManagerTrait, EcuManagerType,
    FunctionalDescriptionConfig, HashMap, Protocol,
    datatypes::{ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition},
    diagservices::DiagServiceResponseType,
};
use cda_plugin_security::DefaultSecurityPluginData;
pub use metadata::MetadataProvider;
pub use resolve::{DidResolver, ResolvedService};
pub use response::ResponseEncoder;
use tokio::sync::RwLock;
pub use uds_helpers::{
    UdsResponse, find_mux_case_prefix, has_mux_case_for_did_exact, parse_mux_coded_value,
};

pub(crate) type CdaEcuManager = Arc<RwLock<EcuManager<DefaultSecurityPluginData>>>;

/// Minimum UDS negative response length: 0x7F + SID + NRC.
const UDS_NEGATIVE_RESPONSE_MIN_LEN: usize = 3;

/// Minimum UDS positive response buffer size: response SID (1) + DID high (1) + DID low (1).
const UDS_POSITIVE_RESPONSE_MIN_SIZE: usize = 3;

#[derive(Clone)]
pub struct ServiceResolver {
    manager: CdaEcuManager,
    ecu_name: String,
}

impl ServiceResolver {
    /// Initialise from an ECU name and a loaded MDD database.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when the CDA `EcuManager` cannot be created
    /// or the base variant fails to activate.
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

        let mut manager = EcuManager::new(
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

    /// Return a [`DidResolver`] for DID-to-service resolution.
    #[must_use]
    pub fn did_resolver(&self) -> DidResolver {
        DidResolver::new(Arc::clone(&self.manager))
    }

    /// Return a [`ResponseEncoder`] for building UDS response bytes.
    #[must_use]
    pub fn response_encoder(&self) -> ResponseEncoder {
        ResponseEncoder::new(Arc::clone(&self.manager))
    }

    /// Return a [`MetadataProvider`] for MDD parameter queries.
    #[must_use]
    pub fn metadata(&self) -> MetadataProvider {
        MetadataProvider::new(Arc::clone(&self.manager))
    }

    /// ECU name as configured at construction time.
    #[must_use]
    pub fn ecu_name(&self) -> &str {
        &self.ecu_name
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
    ///
    /// Returns `DiagServiceError` when `detect_variant` fails and no
    /// variant name was set.
    async fn activate_base_variant(
        manager: &mut EcuManager<DefaultSecurityPluginData>,
    ) -> Result<(), DiagServiceError> {
        // TODO(#16): replace with real variant-identification DID reads.
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

    /// Build default `DoIP` communication parameters for the given addresses.
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
        assert!(!UdsResponse::new(&[0x62, 0xF1, 0x90]).is_negative());
        assert!(!UdsResponse::new(&[0x50, 0x01]).is_negative());
        assert!(UdsResponse::new(&[0x7F, 0x22, 0x31]).is_negative());
        assert!(!UdsResponse::new(&[0x7F]).is_negative());
        assert!(!UdsResponse::new(&[0x7F, 0x22]).is_negative());
    }

    #[test]
    fn test_get_nrc() {
        assert_eq!(UdsResponse::new(&[0x62, 0xF1, 0x90]).nrc(), None);
        assert_eq!(UdsResponse::new(&[0x7F, 0x22, 0x31]).nrc(), Some(0x31));
        assert_eq!(UdsResponse::new(&[0x7F, 0x10, 0x11]).nrc(), Some(0x11));
        assert_eq!(UdsResponse::new(&[0x7F, 0x22, 0x22]).nrc(), Some(0x22));
        assert_eq!(UdsResponse::new(&[0x7F]).nrc(), None);
        assert_eq!(UdsResponse::new(&[0x7F, 0x22]).nrc(), None);
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
            assert_eq!(UdsResponse::new(&[0x7F, sid, nrc]).nrc(), Some(expected));
        }
    }

    #[test]
    fn test_positive_response_sids() {
        assert!(!UdsResponse::new(&[0x50, 0x01, 0x00, 0x32]).is_negative());
        assert!(!UdsResponse::new(&[0x62, 0xF1, 0x90, 0x57]).is_negative());
        assert!(!UdsResponse::new(&[0x67, 0x01, 0x12, 0x34]).is_negative());
        assert!(!UdsResponse::new(&[0x6E, 0xF1, 0x90]).is_negative());
        assert!(!UdsResponse::new(&[0x7E, 0x00]).is_negative());
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
        assert!(!UdsResponse::new(&[]).is_negative());
        assert_eq!(UdsResponse::new(&[]).nrc(), None);
    }
}
