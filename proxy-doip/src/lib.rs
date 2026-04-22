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

//! `DoIP` transport layer for the UDS-to-SOVD proxy.
//!
//! Provides a TCP server that accepts ISO 13400-2 `DoIP` connections,
//! dispatches UDS diagnostic requests to a backend handler, and returns
//! the encoded response.

pub mod handler;
pub mod message;
pub mod server;
pub mod session;

pub use handler::ConnectionHandler;
pub use message::DoIpMessage;
pub use server::DoIpServer;
