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

#![allow(clippy::cast_possible_truncation)]

//! UDS2SOVD Proxy - FLXC1000 Integration Test Client
//!
//! End-to-end test for FLXC1000.mdd (open-source sample ECU).
//! Tests both `ReadDataByIdentifier` (SID 0x22) and `WriteDataByIdentifier` (SID 0x2E).
//!
//! FLXC1000 services:
//!   READ:  `VINDataIdentifier_Read` (0xF190)
//!          `ActiveDiagnosticSessionDataIdentifier_Read` (0xF186)
//!          `Identification_Read` (0xF100)
//!   WRITE: `VINDataIdentifier_Write` (0xF190)
//!
//! Prerequisites:
//!   cargo run --release -- --mdd-file FLXC1000.mdd
//!
//! Usage:
//!   cargo run --release --example `test_client_flxc1000`
//!
//! NOTE: You may see diagnostic engine ERROR logs like:
//!       "Bad payload: `DID_RQ`: Expected [241, 144], got [241, 134]"
//!       These are HARMLESS - they're part of brute-force service resolution. The proxy tries each
//!       service until one matches. All tests pass despite these internal engine errors.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const DOIP_VERSION: u8 = 0x02;
const DOIP_INVERSE: u8 = 0xFD;
const DOIP_ROUTING_ACTIVATION: u16 = 0x0005;
const DOIP_DIAGNOSTIC_MESSAGE: u16 = 0x8001;
const SOURCE_ADDR: u16 = 0x0E80;
const TARGET_ADDR: u16 = 0x0001;

/// `DoIP` diagnostic message header: source address (2) + target address (2).
const DOIP_DIAG_MSG_HEADER_SIZE: usize = 4;

/// UDS service identifiers.
const UDS_SID_RDBI: u8 = 0x22;
const UDS_SID_WDBI: u8 = 0x2E;
const UDS_SID_NEGATIVE_RESPONSE: u8 = 0x7F;

/// Positive response SIDs: service SID | 0x40 per ISO 14229-1.
const UDS_SID_RDBI_RESPONSE: u8 = 0x62; // 0x22 | 0x40
const UDS_SID_WDBI_RESPONSE: u8 = 0x6E; // 0x2E | 0x40

/// Byte offset of the DID field within a positive UDS response (after the SID byte).
const UDS_RESPONSE_DID_START: usize = 1;
/// Byte offset of the end of the DID field (exclusive).
const UDS_RESPONSE_DID_END: usize = 3;
/// Byte offset of the NRC byte within a negative response (0x7F + SID + NRC).
const UDS_NEGATIVE_RESPONSE_NRC_OFFSET: usize = 2;
/// Byte offset of data bytes following the SID + DID in a positive response.
const UDS_RESPONSE_DATA_OFFSET: usize = 3;

fn doip_header(payload_type: u16, len: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(8);
    h.push(DOIP_VERSION);
    h.push(DOIP_INVERSE);
    h.extend_from_slice(&payload_type.to_be_bytes());
    h.extend_from_slice(&len.to_be_bytes());
    h
}

async fn read_doip(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut hdr = [0u8; 8];
    stream.read_exact(&mut hdr).await?;
    let len_bytes: [u8; 4] = hdr.get(4..8).ok_or("invalid header length")?.try_into()?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn activate_routing(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut p = Vec::new();
    p.extend_from_slice(&SOURCE_ADDR.to_be_bytes());
    p.push(0x00); // activation type
    p.extend_from_slice(&[0x00; 4]); // reserved
    let h = doip_header(DOIP_ROUTING_ACTIVATION, p.len() as u32);
    stream.write_all(&h).await?;
    stream.write_all(&p).await?;
    let _ = read_doip(stream).await?;
    Ok(())
}

struct TestResult {
    name: &'static str,
    did: u16,
    passed: bool,
    detail: String,
}

// --- READ tests ---

async fn test_rdbi(
    stream: &mut TcpStream,
    did: u16,
    name: &'static str,
    min_data_bytes: usize,
) -> TestResult {
    let mut uds = Vec::new();
    uds.extend_from_slice(&SOURCE_ADDR.to_be_bytes());
    uds.extend_from_slice(&TARGET_ADDR.to_be_bytes());
    uds.push(UDS_SID_RDBI);
    uds.extend_from_slice(&did.to_be_bytes());

    let h = doip_header(DOIP_DIAGNOSTIC_MESSAGE, uds.len() as u32);
    println!(
        "    [REQ] {:02X?}",
        uds.get(DOIP_DIAG_MSG_HEADER_SIZE..).unwrap_or_default()
    );
    if let Err(e) = stream.write_all(&h).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }
    if let Err(e) = stream.write_all(&uds).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }

    let response = match read_doip(stream).await {
        Ok(r) => r,
        Err(e) => {
            return TestResult {
                name,
                did,
                passed: false,
                detail: format!("recv error: {e}"),
            };
        }
    };

    if response.len() <= DOIP_DIAG_MSG_HEADER_SIZE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: "response too short".into(),
        };
    }

    let uds_resp = response
        .get(DOIP_DIAG_MSG_HEADER_SIZE..)
        .unwrap_or_default();
    println!("    [RSP] {uds_resp:02X?}");

    // Negative response
    let first_byte = uds_resp.first().copied().unwrap_or(0xFF);
    if first_byte == UDS_SID_NEGATIVE_RESPONSE {
        let nrc = uds_resp
            .get(UDS_NEGATIVE_RESPONSE_NRC_OFFSET)
            .copied()
            .unwrap_or(0xFF);
        // NRC 0x22 (conditionsNotCorrect) means the service was resolved in the MDD
        // but the SOVD backend is unreachable — counts as a pass for CI without a SOVD server.
        let passed = nrc == 0x22;
        let label = if passed {
            "no SOVD backend (OK)"
        } else {
            "FAIL"
        };
        return TestResult {
            name,
            did,
            passed,
            detail: format!("NRC 0x{nrc:02X} ({label})"),
        };
    }

    // Must be positive read response (0x62)
    if first_byte != UDS_SID_RDBI_RESPONSE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("unexpected SID 0x{first_byte:02X}"),
        };
    }

    let resp_did = uds_resp
        .get(UDS_RESPONSE_DID_START..UDS_RESPONSE_DID_END)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_be_bytes);
    if resp_did != did {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("DID mismatch: got 0x{resp_did:04X}"),
        };
    }

    let data = uds_resp.get(UDS_RESPONSE_DATA_OFFSET..).unwrap_or_default();
    if data.len() < min_data_bytes {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!(
                "expected >= {} data bytes, got {} bytes {:02X?}",
                min_data_bytes,
                data.len(),
                data
            ),
        };
    }

    TestResult {
        name,
        did,
        passed: true,
        detail: format!("{} bytes {:02X?}", data.len(), data),
    }
}

// --- WRITE tests ---

async fn test_wdbi(
    stream: &mut TcpStream,
    did: u16,
    name: &'static str,
    data: &[u8],
) -> TestResult {
    let mut uds = Vec::new();
    uds.extend_from_slice(&SOURCE_ADDR.to_be_bytes());
    uds.extend_from_slice(&TARGET_ADDR.to_be_bytes());
    uds.push(UDS_SID_WDBI);
    uds.extend_from_slice(&did.to_be_bytes());
    uds.extend_from_slice(data);

    let h = doip_header(DOIP_DIAGNOSTIC_MESSAGE, uds.len() as u32);
    println!(
        "    [REQ] {:02X?}",
        uds.get(DOIP_DIAG_MSG_HEADER_SIZE..).unwrap_or_default()
    );
    if let Err(e) = stream.write_all(&h).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }
    if let Err(e) = stream.write_all(&uds).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }

    let response = match read_doip(stream).await {
        Ok(r) => r,
        Err(e) => {
            return TestResult {
                name,
                did,
                passed: false,
                detail: format!("recv error: {e}"),
            };
        }
    };

    if response.len() <= DOIP_DIAG_MSG_HEADER_SIZE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: "response too short".into(),
        };
    }

    let uds_resp = response
        .get(DOIP_DIAG_MSG_HEADER_SIZE..)
        .unwrap_or_default();
    println!("    [RSP] {uds_resp:02X?}");

    let first_byte = uds_resp.first().copied().unwrap_or(0xFF);
    if first_byte == UDS_SID_NEGATIVE_RESPONSE {
        let nrc = uds_resp
            .get(UDS_NEGATIVE_RESPONSE_NRC_OFFSET)
            .copied()
            .unwrap_or(0xFF);
        // NRC 0x22 means service was resolved but SOVD backend unreachable — pass in CI.
        let passed = nrc == 0x22;
        let label = if passed {
            "no SOVD backend (OK)"
        } else {
            "FAIL"
        };
        return TestResult {
            name,
            did,
            passed,
            detail: format!("NRC 0x{nrc:02X} ({label})"),
        };
    }

    // Must be positive write response (0x6E)
    if first_byte != UDS_SID_WDBI_RESPONSE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("unexpected SID 0x{first_byte:02X}"),
        };
    }

    let resp_did = uds_resp
        .get(UDS_RESPONSE_DID_START..UDS_RESPONSE_DID_END)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_be_bytes);
    if resp_did != did {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("DID mismatch: got 0x{resp_did:04X}"),
        };
    }

    TestResult {
        name,
        did,
        passed: true,
        detail: format!("positive response ({} bytes)", uds_resp.len()),
    }
}

// --- NRC test (DID not supported) ---

#[allow(dead_code)]
async fn test_nrc(
    stream: &mut TcpStream,
    did: u16,
    name: &'static str,
    expected_nrc: u8,
) -> TestResult {
    let mut uds = Vec::new();
    uds.extend_from_slice(&SOURCE_ADDR.to_be_bytes());
    uds.extend_from_slice(&TARGET_ADDR.to_be_bytes());
    uds.push(0x22);
    uds.extend_from_slice(&did.to_be_bytes());

    let h = doip_header(DOIP_DIAGNOSTIC_MESSAGE, uds.len() as u32);
    if let Err(e) = stream.write_all(&h).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }
    if let Err(e) = stream.write_all(&uds).await {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("send error: {e}"),
        };
    }

    let response = match read_doip(stream).await {
        Ok(r) => r,
        Err(e) => {
            return TestResult {
                name,
                did,
                passed: false,
                detail: format!("recv error: {e}"),
            };
        }
    };

    if response.len() <= DOIP_DIAG_MSG_HEADER_SIZE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: "response too short".into(),
        };
    }

    let uds_resp = response
        .get(DOIP_DIAG_MSG_HEADER_SIZE..)
        .unwrap_or_default();

    let first_byte = uds_resp.first().copied().unwrap_or(0xFF);
    if first_byte != UDS_SID_NEGATIVE_RESPONSE {
        return TestResult {
            name,
            did,
            passed: false,
            detail: format!("expected NRC but got positive response: {uds_resp:02X?}"),
        };
    }

    let nrc = uds_resp
        .get(UDS_NEGATIVE_RESPONSE_NRC_OFFSET)
        .copied()
        .unwrap_or(0xFF);
    if nrc == expected_nrc {
        TestResult {
            name,
            did,
            passed: true,
            detail: format!("NRC 0x{nrc:02X} (expected)"),
        }
    } else {
        TestResult {
            name,
            did,
            passed: false,
            detail: format!("NRC 0x{nrc:02X}, expected 0x{expected_nrc:02X}"),
        }
    }
}

fn print_result(result: &TestResult) {
    let status = if result.passed { "OK" } else { "FAIL" };
    println!(
        "  [{:16}] DID 0x{:04X}  {:4}  {}",
        result.name, result.did, status, result.detail
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("UDS2SOVD Proxy - FLXC1000 Integration Test");
    println!("{}", "=".repeat(70));
    println!("Requires: cargo run --release -- --mdd-file FLXC1000.mdd");
    println!();

    let mut stream = TcpStream::connect("127.0.0.1:13400").await?;
    println!("[CONNECT] Connected to proxy at 127.0.0.1:13400");
    activate_routing(&mut stream).await?;
    println!("[ACTIVATE] Routing activated");
    println!();

    let mut total: usize = 0;
    let mut passed: usize = 0;

    // --- READ service tests ---
    println!("READ Service Tests (SID 0x22):");
    println!("{}", "-".repeat(70));

    let read_tests = vec![
        // FLXC1000 READ services (resolved via PHYS-CONST brute-force)
        (0xF190, "VINDataIdentifier_Read", 1), // VINDataIdentifier_Read
        (0xF186, "ActiveDiagnosticSessionDataIdentifier_Read", 1), // ActiveDiagnosticSession_Read
        (0xF100, "Identification_Read", 1),    // Identification_Read
    ];

    for (did, name, min_bytes) in &read_tests {
        let result = test_rdbi(&mut stream, *did, name, *min_bytes).await;
        print_result(&result);
        println!("{}", "-".repeat(70));
        total = total.saturating_add(1);
        if result.passed {
            passed = passed.saturating_add(1);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // --- WRITE service tests ---
    println!();
    println!("WRITE Service Tests (SID 0x2E):");
    println!("{}", "-".repeat(70));

    // VINDataIdentifier_Write: DID 0xF190 + 17 bytes VIN
    let vin_data: Vec<u8> = b"WBADT43452G123456".to_vec();
    let result = test_wdbi(&mut stream, 0xF190, "VIN_Write", &vin_data).await;
    print_result(&result);
    println!("{}", "-".repeat(70));
    total = total.saturating_add(1);
    if result.passed {
        passed = passed.saturating_add(1);
    }

    // --- NRC tests (unsupported DIDs) ---
    println!();
    println!("NRC Tests (unsupported DIDs -> NRC 0x31):");
    println!("{}", "-".repeat(70));

    let nrc_tests = vec![
        (0xF197, "Unknown_F197", 0x31), // Not in FLXC1000 MDD
        (0xF150, "Unknown_F150", 0x31), // Not in FLXC1000 MDD
        (0x2504, "Unknown_2504", 0x31), // IPN15-only DID
    ];

    for (did, name, expected_nrc) in &nrc_tests {
        let result = test_nrc(&mut stream, *did, name, *expected_nrc).await;
        print_result(&result);
        total = total.saturating_add(1);
        if result.passed {
            passed = passed.saturating_add(1);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // --- Summary ---
    let failed = total.saturating_sub(passed);
    println!();
    println!("{}", "=".repeat(70));
    println!("Results: {passed}/{total} passed, {failed} failed");
    println!("{}", "=".repeat(70));

    if failed == 0 {
        println!("All FLXC1000 tests passed!");
        Ok(())
    } else {
        Err(format!("{failed} test(s) failed").into())
    }
}
