<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# 🔌 UDS-to-SOVD Proxy 🚗

This repository contains the UDS-to-SOVD Proxy of the Eclipse OpenSOVD project and its documentation.

In the SOVD (Service-Oriented Vehicle Diagnostics) context, the UDS-to-SOVD Proxy serves as a
protocol translation gateway between legacy UDS (Unified Diagnostic Services) based diagnostic
tools and the modern SOVD-based diagnostic architecture.

It accepts UDS requests over DoIP (Diagnostics over IP), resolves the corresponding SOVD service
using the diagnostic description (MDD) of the ECU, and translates them into SOVD REST API calls.
The SOVD responses are then encoded back into UDS format and returned to the requesting tool.

This enables existing UDS-based diagnostic tools and workflows to seamlessly interact with
SOVD-enabled vehicle architectures without modification.

## goals

- 🔄 transparent UDS ↔ SOVD protocol translation
- 🚀 high performance (asynchronous I/O)
- 🤏 low memory and disk-space consumption
- 🛡️ safe & secure
- ⚡ fast startup

## features

- **MDD-Agnostic**: Works with any valid MDD file
- **DoIP Server**: ISO 13400-2 compliant, port configurable (default: `13400`)
- **SOVD Mapping**: UDS ↔ SOVD REST API conversion
- **Mock Gateway**: Built-in SOVD mock responses for testing
- **Service Resolution**: DID → service mapping via MDD (MUX map or brute-force)

## prerequisites

To run the proxy you will need at least one `MDD` file. Check out [eclipse-opensovd/odx-converter](https://github.com/eclipse-opensovd/odx-converter) on how to create `MDD`(s) from ODX.

Sample ODX/MDD files are available in the CDA repository: [testcontainer/odx](https://github.com/eclipse-opensovd/classic-diagnostic-adapter/tree/main/testcontainer/odx)

Once you have the `MDD`(s) you can place them in `testcontainer/mdd/` or pass the path via `--mdd-dir`.

### build the executable

```shell
cargo build --release
```

### running

Ensure that the config (`examples/config.toml`) fits your setup:

- `doip_port` is set to the desired DoIP server port (default: `13400`)
- `gateway_url` points to the SOVD gateway (CDA or mock)
- `mock_gateway = true` enables built-in mock responses for testing without a real CDA

Run the proxy:

```shell
cargo run --release -- --mdd-dir testcontainer/mdd
```

Or with a specific MDD file:

```shell
cargo run --release -- --mdd-file FLXC1000.mdd
```

### running with SOVD Server

To use the proxy with a real SOVD Server instance, set `mock_gateway = false` in `examples/config.toml` and point `gateway_url` to the SOVD Server endpoint.

## architecture

```
DoIP Client (port 13400)
    ↓ UDS request (0x22 DID)
Proxy (service resolution via MDD)
    ↓ SOVD REST (GET /data/vindataidentifier_read)
Mock Gateway OR Real SOVD Server
    ↓ SOVD JSON response
Proxy (MDD-based UDS encoding)
    ↓ UDS response (0x62 DID data)
DoIP Client
```

## directory structure

- `proxy-core/`: Shared types, errors, MDD engine, and `DiagHandler` trait
- `proxy-doip/`: DoIP transport layer (ISO 13400-2) — server and session handling
- `proxy-sovd/`: SOVD REST client and UDS ↔ SOVD mapping
- `proxy-main/`: Binary entry point, CLI, configuration, and example clients
- `testcontainer/mdd/`: MDD files (FLXC1000.mdd)
- `proxy-main/examples/`: Test clients for each MDD

## configuration

Edit `examples/config.toml`:

- `doip_port = 13_400`: DoIP server port
- `mock_gateway = true`: Use built-in mock responses
- `gateway_url`: SOVD gateway endpoint
- MDD directory: `--mdd-dir testcontainer/mdd` (default)

## developing

### pre commit

```shell
uv run https://raw.githubusercontent.com/eclipse-opensovd/cicd-workflows/main/run_checks.py
```

### codestyle

see [codestyle](CODESTYLE.md)

### testing

#### unit tests

Unittests are placed in the relevant module as usual in rust:

```rust
...
#[cfg(test)]
mod test {
    ...
}
```

Run unit tests with:

```shell
cargo test --locked --lib
```

#### integration tests
