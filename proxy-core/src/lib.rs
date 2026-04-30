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

//! Core types and traits shared across all proxy crates.
//!
//! Defines configuration, error types, and the MDD-driven [`ServiceResolver`] facade
//! with three composable sub-components:
//!
//! - [`DidResolver`] — DID-to-service resolution
//! - [`ResponseEncoder`] — UDS response encoding
//! - [`MetadataProvider`] — MDD parameter metadata queries

pub mod config;
pub mod error;
pub mod service_resolver;

pub use config::Config;
pub use error::{ProxyError, Result};
pub use service_resolver::{
    DidResolver, MetadataProvider, ResolvedService, ResponseEncoder, ServiceResolver, ServiceType,
};
