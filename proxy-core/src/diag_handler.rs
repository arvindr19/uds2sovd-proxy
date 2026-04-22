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

use async_trait::async_trait;

use crate::error::Result;

/// Trait for processing UDS diagnostic requests through a backend.
#[async_trait]
pub trait DiagHandler: Send + Sync {
    /// Process a `ReadDataByIdentifier` (0x22) request.
    ///
    /// `did` is the extracted 16-bit Data Identifier.
    /// `uds_request` is the full UDS request bytes including the SID byte.
    ///
    /// Returns the complete UDS response bytes (positive or negative).
    async fn handle_read_did(&self, did: u16, uds_request: &[u8]) -> Result<Vec<u8>>;

    /// Process a `WriteDataByIdentifier` (0x2E) request.
    ///
    /// `did` is the extracted 16-bit Data Identifier.
    /// `uds_request` is the full UDS request bytes including the SID byte.
    ///
    /// Returns the complete UDS response bytes (positive or negative).
    async fn handle_write_did(&self, did: u16, uds_request: &[u8]) -> Result<Vec<u8>>;
}
