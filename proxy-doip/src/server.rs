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

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use proxy_core::{Config, DiagHandler, Result};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::handler::ConnectionHandler;

/// `DoIP` TCP server that accepts connections and spawns per-connection handlers.
///
/// Each incoming TCP connection is handled by a [`ConnectionHandler`] that
/// reads `DoIP` frames, dispatches UDS requests to the injected
/// [`DiagHandler`], and returns the encoded response.
///
/// - TODO(doip): Add UDP announcement/discovery (ISO 13400-2 §7.3) so
///   diagnostic tools can discover the proxy via Vehicle Identification.
/// - TODO(doip): Add TLS support for secure `DoIP` connections.
/// - TODO(doip): Add per-connection inactivity timeout (`T_TCP_General_Inactivity`).
pub struct DoIpServer {
    /// Shared proxy configuration.
    config: Arc<Config>,
    /// Backend diagnostic handler injected at construction time.
    diag_handler: Arc<dyn DiagHandler>,
    /// Number of currently active TCP connections.
    active_connections: Arc<AtomicUsize>,
}

impl DoIpServer {
    /// Create a new `DoIP` server with a diagnostic handler.
    ///
    /// The handler is constructed and wired in `proxy-main`, keeping the
    /// `DoIP` layer decoupled from the concrete SOVD backend.
    pub fn new(config: Arc<Config>, diag_handler: Arc<dyn DiagHandler>) -> Self {
        Self {
            config,
            diag_handler,
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Start the `DoIP` TCP server and accept connections in a loop.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind or accept connections.
    pub async fn run(&self) -> Result<()> {
        let addr = format!(
            "{}:{}",
            self.config.server.bind_address, self.config.server.doip_port
        );

        info!("Starting DoIP server on {}", addr);

        let listener = TcpListener::bind(&addr).await?;
        info!("════════════════════════════════════════════════════════════════════════");
        info!("DoIP server listening on {}", addr);
        info!("UDS2SOVD Proxy ready to accept connections");
        info!("════════════════════════════════════════════════════════════════════════");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let previous = self.active_connections.fetch_add(1, Ordering::AcqRel);
                    let limit = self.config.server.max_connections;
                    if previous >= limit {
                        self.active_connections.fetch_sub(1, Ordering::AcqRel);
                        warn!(
                            "Rejecting connection from {} because active connection limit {}/{} \
                             is reached",
                            peer_addr, previous, limit,
                        );
                        drop(stream);
                        continue;
                    }

                    let active_now = previous.saturating_add(1);
                    info!(
                        "Accepted connection from {} (active connections: {}/{})",
                        peer_addr, active_now, limit,
                    );

                    let config = Arc::clone(&self.config);
                    let diag_handler = Arc::clone(&self.diag_handler);
                    let active_connections = Arc::clone(&self.active_connections);

                    // Spawn handler for this connection
                    tokio::spawn(async move {
                        let _connection_slot = ActiveConnectionSlot::new(active_connections);
                        let handler = ConnectionHandler::new(config, diag_handler, stream);
                        if let Err(e) = handler.handle().await {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Decrements the active connection counter when a connection task ends.
struct ActiveConnectionSlot {
    counter: Arc<AtomicUsize>,
}

impl ActiveConnectionSlot {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { counter }
    }
}

impl Drop for ActiveConnectionSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}
