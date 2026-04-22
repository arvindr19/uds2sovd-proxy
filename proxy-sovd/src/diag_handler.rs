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

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use proxy_core::{Config, DiagHandler, ProxyError, Result, ServiceResolver, error::UdsError};
use tracing::info;

use crate::mapper::SovdMapper;

/// SOVD-backed implementation of [`DiagHandler`].
///
/// Combines MDD-based service resolution ([`ServiceResolver`]) with SOVD
/// gateway communication ([`SovdMapper`]) to process UDS diagnostic requests.
///
/// Constructed in `proxy-main` and injected into the `DoIP` server as
/// `Arc<dyn DiagHandler>`.
pub struct SovdDiagHandler {
    /// Shared proxy configuration.
    config: Arc<Config>,
    /// SOVD gateway mapper for request/response translation.
    mapper: SovdMapper,
    /// Per-ECU service resolvers keyed by ECU name.
    ecu_managers: Arc<HashMap<String, ServiceResolver>>,
}

impl SovdDiagHandler {
    /// Create a new SOVD diagnostic handler.
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        mapper: SovdMapper,
        ecu_managers: Arc<HashMap<String, ServiceResolver>>,
    ) -> Self {
        Self {
            config,
            mapper,
            ecu_managers,
        }
    }

    fn ecu_manager(&self) -> Option<&ServiceResolver> {
        let ecu_name = &self.config.ecu.default_name;
        self.ecu_managers
            .get(ecu_name)
            .or_else(|| self.ecu_managers.values().next())
    }
}

#[async_trait]
impl DiagHandler for SovdDiagHandler {
    async fn handle_read_did(&self, did: u16, uds_request: &[u8]) -> Result<Vec<u8>> {
        let mgr = self
            .ecu_manager()
            .ok_or_else(|| ProxyError::Mdd("No MDD database loaded".to_string()))?;

        let (service_name, parsed_data) = mgr
            .resolve_read_service(did, uds_request)
            .await
            .ok_or(ProxyError::Uds(UdsError::InvalidDid(did)))?;

        info!("[MDD] READ service found: '{}'", service_name);

        self.mapper
            .process_read_data_request(
                did,
                uds_request,
                Some(mgr),
                &service_name,
                Some(parsed_data),
            )
            .await
    }

    async fn handle_write_did(&self, did: u16, uds_request: &[u8]) -> Result<Vec<u8>> {
        let mgr = self
            .ecu_manager()
            .ok_or_else(|| ProxyError::Mdd("No MDD database loaded".to_string()))?;

        let (service_name, parsed_data) = mgr
            .resolve_write_service(did, uds_request)
            .await
            .ok_or(ProxyError::Uds(UdsError::InvalidDid(did)))?;

        info!("[MDD] WRITE service found: '{}'", service_name);

        self.mapper
            .process_write_data_request(did, uds_request, &service_name, parsed_data)
            .await
    }
}
