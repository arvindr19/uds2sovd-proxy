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

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_database::{datatypes::DiagnosticDatabase, load_ecudata};
use cda_interfaces::{HashMap, datatypes::FlatbBufConfig};
use clap::Parser;
use proxy_core::{Cli, Config, Result, ServiceResolver, error::ProxyError};
use proxy_doip::DoIpServer;
use proxy_sovd::{SovdClient, SovdDiagHandler, SovdMapper};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli)?;

    init_logging(&config);

    info!("Starting UDS2SOVD Proxy");
    info!("Configuration loaded (TOML: {})", cli.config.display());
    info!("DoIP server port: {}", config.server.doip_port);

    let mdd_path = resolve_mdd_path(&cli.mdd_file, &cli.mdd_dir);
    let (ecu_name, db) = load_mdd(&mdd_path)?;

    let mut final_config = config;
    final_config.ecu.default_name.clone_from(&ecu_name);

    let config = Arc::new(final_config);

    // Create ServiceResolver for the loaded ECU.
    let manager =
        ServiceResolver::new(db, config.ecu.logical_address, config.server.source_address)
            .await
            .map_err(|e| ProxyError::Mdd(format!("Failed to create ServiceResolver: {e}")))?;

    let ecu_managers = Arc::new(HashMap::from_iter([(ecu_name, manager)]));
    info!(
        "ServiceResolver ready for ECU '{}'",
        config.ecu.default_name
    );

    // Create SOVD client, mapper, and diagnostic handler
    let sovd_client = SovdClient::new(config.sovd.clone())
        .map_err(|e| ProxyError::Config(format!("Failed to create SOVD client: {e}")))?;
    let sovd_mapper = SovdMapper::new(&config, sovd_client);
    let diag_handler = Arc::new(SovdDiagHandler::new(
        Arc::clone(&config),
        sovd_mapper,
        Arc::clone(&ecu_managers),
    ));

    let server = DoIpServer::new(Arc::clone(&config), diag_handler);
    info!("UDS2SOVD Proxy is running");

    tokio::select! {
        result = server.run() => result?,
        () = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {},
                Err(e) => {
                    error!("Failed to register Ctrl+C handler: {e}");
                    // Do not resolve — avoid falsely triggering the shutdown arm.
                    std::future::pending::<()>().await;
                }
            }
        } => {
            info!("Received shutdown signal, stopping...");
        }
    }

    Ok(())
}

/// Initialize tracing and logging for the proxy.
fn init_logging(config: &Config) {
    let log_level = match config.logging.level {
        proxy_core::LogLevel::Error => "error",
        proxy_core::LogLevel::Warn => "warn",
        proxy_core::LogLevel::Info => "info",
        proxy_core::LogLevel::Debug => "debug",
        proxy_core::LogLevel::Trace => "trace",
    };

    let filter_directive =
        format!("{log_level},cda_core=off,cda_database=warn,cda_interfaces=warn,cda_comm_uds=warn");

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&filter_directive));

    let fmt_layer = tracing_subscriber::fmt::layer();
    let registry = tracing_subscriber::registry().with(env_filter);

    if config.logging.format == proxy_core::LogFormat::Json {
        registry.with(fmt_layer.json()).init();
    } else {
        registry.with(fmt_layer.pretty()).init();
    }
}

/// Resolve the MDD file path: if it's a bare filename, join with `mdd_dir`.
fn resolve_mdd_path(mdd_file: &Path, mdd_dir: &Path) -> PathBuf {
    if mdd_file.is_absolute() || mdd_file.parent().is_some_and(|p| p != Path::new("")) {
        mdd_file.to_path_buf()
    } else {
        mdd_dir.join(mdd_file)
    }
}

/// Load a single MDD file and create a diagnostic database.
///
/// Reads the MDD metadata database from the specified file path, then initializes
/// a `DiagnosticDatabase` for the ECU. Returns both the ECU name and the database.
///
/// # Errors
/// - The file path contains invalid UTF-8
/// - The MDD file cannot be loaded via `load_ecudata`
/// - The diagnostic database cannot be created from the loaded data
fn load_mdd(mdd_path: &Path) -> Result<(String, DiagnosticDatabase)> {
    let mdd_str = mdd_path.to_str().ok_or_else(|| {
        ProxyError::Config(format!("Invalid UTF-8 in MDD path: {}", mdd_path.display()))
    })?;

    info!("Loading MDD: {}", mdd_path.display());

    let (ecu_name, diagnostic_data) = load_ecudata(mdd_str).map_err(|e| {
        ProxyError::Mdd(format!(
            "Failed to load MDD '{}': {}",
            mdd_path.display(),
            e
        ))
    })?;

    let db = DiagnosticDatabase::new_from_bytes(
        mdd_str.to_string(),
        diagnostic_data,
        FlatbBufConfig::default(),
    )
    .map_err(|e| {
        ProxyError::Mdd(format!(
            "Failed to create database from '{}': {}",
            mdd_path.display(),
            e
        ))
    })?;

    Ok((ecu_name, db))
}
