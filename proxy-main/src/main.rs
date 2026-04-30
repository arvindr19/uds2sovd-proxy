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
use proxy_core::{Config, Result, ServiceResolver, error::ProxyError};
use proxy_doip::DoIpServer;
use proxy_sovd::{SovdClient, SovdDiagHandler, SovdMapper};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Command-line arguments for the UDS-to-SOVD proxy.

#[derive(Parser, Debug)]
#[command(name = "uds2sovdproxy", about = "UDS to SOVD proxy with DoIP server")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/config.toml")]
    config: String,

    /// Override log level
    #[arg(short, long)]
    log_level: Option<String>,

    /// MDD file to load. Absolute path, or filename resolved under --mdd-dir.
    #[arg(short, long, required = true)]
    mdd_file: String,

    /// Directory searched when --mdd-file is a relative filename
    #[arg(long, default_value = "testcontainer/mdd")]
    mdd_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = Config::from_file(&args.config).unwrap_or_else(|e| {
        eprintln!(
            "Warning: Could not load config file '{}': {e} — using defaults",
            args.config
        );
        Config::default()
    });

    init_logging(&config, args.log_level.as_deref());

    info!("Starting UDS2SOVD Proxy");
    info!("Configuration loaded from: {}", args.config);
    info!("DoIP server port: {}", config.server.doip_port);

    let mdd_path = {
        let p = PathBuf::from(&args.mdd_file);
        if p.is_absolute() || p.parent().is_some_and(|parent| parent != Path::new("")) {
            p
        } else {
            Path::new(&args.mdd_dir).join(&p)
        }
    };

    let (ecu_name, db) = load_mdd(&mdd_path)?;

    let mut final_config = config;
    final_config.ecu.default_name.clone_from(&ecu_name);

    let config = Arc::new(final_config);

    // Create ServiceResolver for the loaded ECU.
    let manager = ServiceResolver::new(
        ecu_name.clone(),
        db,
        config.ecu.logical_address,
        config.server.source_address,
    )
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
///
/// Configures the tracing subscriber with the specified log level (or override),
/// then initializes the global subscriber with either JSON or pretty formatting.
fn init_logging(config: &Config, log_level_override: Option<&str>) {
    let log_level = log_level_override.unwrap_or(&config.logging.level);

    let filter_directive =
        format!("{log_level},cda_core=off,cda_database=warn,cda_interfaces=warn,cda_comm_uds=warn");

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&filter_directive));

    let fmt_layer = tracing_subscriber::fmt::layer();
    let registry = tracing_subscriber::registry().with(env_filter);

    if config.logging.format == "json" {
        registry.with(fmt_layer.json()).init();
    } else {
        registry.with(fmt_layer.pretty()).init();
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
