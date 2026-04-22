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

//! SOVD gateway integration for the UDS-to-SOVD proxy.
//!
//! Provides the [`SovdDiagHandler`] implementation of [`proxy_core::DiagHandler`]
//! that translates UDS requests into SOVD REST calls and encodes the
//! responses back to UDS using MDD metadata.

pub mod client;
pub mod diag_handler;
pub mod mapper;
pub mod schema;

pub use client::SovdClient;
pub use diag_handler::SovdDiagHandler;
pub use mapper::SovdMapper;
