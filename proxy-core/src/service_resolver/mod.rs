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

pub(crate) mod metadata;
pub(crate) mod resolve;
pub(crate) mod response;
pub(crate) mod uds_helpers;

use std::sync::Arc;

use cda_core::{DiagServiceResponseStruct, EcuManager as CdaEcuManager};
use cda_database::datatypes::DiagnosticDatabase;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, EcuManager as EcuManagerTrait, EcuManagerType,
    FunctionalDescriptionConfig, HashMap, Protocol, ResponseParameterInfo,
    datatypes::{ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition},
    diagservices::DiagServiceResponseType,
};
use cda_plugin_security::DefaultSecurityPluginData;
pub(crate) use metadata::MetadataProvider;
pub(crate) use resolve::DidResolver;
pub use resolve::{ResolvedService, ServiceType};
pub(crate) use response::ResponseEncoder;
use tokio::sync::RwLock;
pub use uds_helpers::find_mux_case_prefix;

pub(crate) type ManagerHandle = Arc<RwLock<CdaEcuManager<DefaultSecurityPluginData>>>;

/// Minimum UDS positive response buffer size: response SID (1) + DID high (1) + DID low (1).
pub(crate) const UDS_POSITIVE_RESPONSE_MIN_SIZE: usize = 3;

/// UDS Service Identifiers (SIDs) for diagnostic services.
///
/// Proxy-level definitions independent of CDA library.
pub mod uds_service_ids {
    /// Session Control
    pub const SESSION_CONTROL: u8 = 0x10;
    /// ECU Reset
    pub const ECU_RESET: u8 = 0x11;
    /// Clear Diagnostic Information
    pub const CLEAR_DIAGNOSTIC_INFORMATION: u8 = 0x14;
    /// Read DTC Information
    pub const READ_DTC_INFORMATION: u8 = 0x19;
    /// Read Data By Identifier
    pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
    /// Security Access
    pub const SECURITY_ACCESS: u8 = 0x27;
    /// Communication Control
    pub const COMMUNICATION_CONTROL: u8 = 0x28;
    /// Authentication
    pub const AUTHENTICATION: u8 = 0x29;
    /// Write Data By Identifier
    pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
    /// Input/Output Control By Identifier
    pub const INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: u8 = 0x2F;
    /// Routine Control
    pub const ROUTINE_CONTROL: u8 = 0x31;
    /// Request Download
    pub const REQUEST_DOWNLOAD: u8 = 0x34;
    /// Transfer Data
    pub const TRANSFER_DATA: u8 = 0x36;
    /// Request Transfer Exit
    pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
    /// Tester Present
    pub const TESTER_PRESENT: u8 = 0x3E;
    /// Control DTC Setting
    pub const CONTROL_DTC_SETTING: u8 = 0x85;
    /// Negative Response
    pub const NEGATIVE_RESPONSE: u8 = 0x7F;
}

pub struct ServiceResolver {
    /// DID-to-service resolution.
    resolver: DidResolver,
    /// UDS response encoding from SOVD JSON data.
    encoder: ResponseEncoder,
    /// MDD metadata queries (request/response parameter info, MUX cases).
    metadata: MetadataProvider,
}

impl ServiceResolver {
    /// Initialise from a loaded MDD database.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when the CDA `EcuManager` cannot be created
    /// or the base variant fails to activate.
    pub async fn new(
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

        let handle: ManagerHandle = Arc::new(RwLock::new(manager));

        let metadata = MetadataProvider::new(Arc::clone(&handle));
        Ok(Self {
            resolver: DidResolver::new(Arc::clone(&handle)),
            encoder: ResponseEncoder::new(Arc::clone(&handle), metadata.clone()),
            metadata,
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
    /// <https://github.com/eclipse-opensovd/uds2sovd-proxy/issues/16\>
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
        manager: &mut CdaEcuManager<DefaultSecurityPluginData>,
    ) -> Result<(), DiagServiceError> {
        // TODO(#16): replace with real variant-identification DID reads.
        let dummy_response = DiagServiceResponseStruct {
            service: DiagComm {
                name: String::new(),
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            data: Vec::new(),
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

    /// Resolve the best-matching MDD service for a UDS DID request.
    ///
    /// Returns `None` when no matching service is found in the MDD.
    pub async fn resolve(
        &self,
        service_type: ServiceType,
        did: u16,
        uds_bytes: &[u8],
    ) -> Option<ResolvedService> {
        self.resolver.resolve(service_type, did, uds_bytes).await
    }

    /// Build UDS response bytes from SOVD JSON data using MDD metadata.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when the response cannot be encoded.
    pub async fn build_response(
        &self,
        service_name: &str,
        sid: u8,
        did: u16,
        response_data: HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        self.encoder
            .build_response(service_name, sid, did, response_data)
            .await
    }

    /// Return the best available POS-RESPONSE metadata for `service_name` + `did`.
    ///
    /// Tries enriched (MUX-substituted) metadata first; falls back to the plain
    /// POS-RESPONSE layout when the enriched path fails.
    /// NOTE:
    /// This is intended for the mock response path only.  Once the SOVD server
    /// supplies real data this accessor is no longer required externally.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when both the enriched and plain metadata
    /// lookups fail.
    pub async fn get_response_metadata(
        &self,
        service_name: &str,
        did: u16,
    ) -> Result<Vec<ResponseParameterInfo>, DiagServiceError> {
        self.metadata.get_response_metadata(service_name, did).await
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
}
