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

//! UDS helper functions and types.
//!
//! Pure functions used across the `service_resolver` module: DID extraction,
//! MUX-case matching, value encoding, and payload construction.

use cda_interfaces::{
    CompuScaleInfo, DiagComm, DiagCommType, ResponseParameterInfo, ServiceParameterMetadata,
    ServicePayload,
};

/// Extract the 16-bit DID from UDS payload bytes at offset 1–2.
///
/// Returns `None` if the slice has fewer than 3 bytes.
pub(super) fn extract_did_from_uds(data: &[u8]) -> Option<u16> {
    let b1 = *data.get(1)?;
    let b2 = *data.get(2)?;
    Some(u16::from_be_bytes([b1, b2]))
}

/// Map a UDS SID to its [`DiagCommType`].
///
/// Falls back to [`DiagCommType::Data`] for unrecognised SIDs so that the
/// caller always receives a usable type rather than an error.
pub(super) fn diag_comm_type(service_id: u8) -> DiagCommType {
    DiagCommType::try_from(service_id).unwrap_or(DiagCommType::Data)
}

/// Create a `ServicePayload` from raw UDS bytes with default addresses.
pub(super) fn make_service_payload(data: &[u8]) -> ServicePayload {
    ServicePayload {
        data: data.to_vec(),
        source_address: 0,
        target_address: 0,
        new_session: None,
        new_security: None,
    }
}

/// Encode an unsigned integer as big-endian bytes (minimum width).
///
/// Zero encodes as `[0x00]`.
pub(super) fn encode_unsigned_be(num: u64) -> Vec<u8> {
    if num == 0 {
        return vec![0x00];
    }
    num.to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect()
}

/// Parse a MUX case `coded_value` string as a numeric DID value.
///
/// MDD stores MUX case limits as strings that may be float-formatted
/// (e.g. `"61699.0"`) or integer-formatted (e.g. `"61699"`).
#[must_use]
pub(super) fn parse_mux_coded_value(coded_value: &str) -> Option<u64> {
    let trimmed = coded_value.trim();
    // Try integer parsing first; fall back to float (MDD may store values like "61699.0").
    // The bounds check (`>= 0.0` and `<= u64::MAX as f64`) ensures the value fits before
    // the narrowing cast.  DIDs are 16-bit so precision loss from f64 never occurs in practice.
    #[allow(
        clippy::cast_precision_loss,   // u64::MAX as f64 is safe for the upper-bound comparison
        clippy::cast_possible_truncation, // guarded by the bounds check above
        clippy::cast_sign_loss         // guarded by the `>= 0.0` check above
    )]
    trimmed.parse::<u64>().ok().or_else(|| {
        let v = trimmed.parse::<f64>().ok()?;
        (v >= 0.0 && v <= u64::MAX as f64).then_some(v as u64)
    })
}

/// Find the MUX case prefix that covers a given DID in response metadata.
///
/// MDD `__mux_case__` entries store only the **`lower_limit`** of their range
/// (e.g. a case with `coded_value: "61697"` covering DIDs 0xF101
/// through 0xF140).  A DID like 0xF103 (61699) has no exact match
/// but falls in that range.
///
/// This function uses **floor-based matching**: collect all `__mux_case__`
/// lower bounds, sort them, and find the case with the largest lower bound
/// that does not exceed the DID.  This correctly handles both single-value
/// MUX cases (e.g. 0x7007) and range cases (e.g. 0xD100–0xD150).
#[must_use]
pub(crate) fn find_mux_case_prefix(meta: &[ResponseParameterInfo], did: u16) -> Option<String> {
    let did_val = u64::from(did);

    // Collect (lower_bound, case_name) for all MUX case entries.
    let mut mux_entries: Vec<(u64, &str)> = meta
        .iter()
        .filter_map(|p| {
            let case_name = p.name.strip_prefix("__mux_case__/")?;
            if let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
            {
                let lower = parse_mux_coded_value(coded_value)?;
                Some((lower, case_name))
            } else {
                None
            }
        })
        .collect();

    if mux_entries.is_empty() {
        return None;
    }

    // Sort by lower bound ascending.
    mux_entries.sort_by_key(|&(lb, _)| lb);

    // Floor match: largest lower_bound ≤ DID.
    let matched = mux_entries.iter().rev().find(|&&(lb, _)| lb <= did_val)?;

    Some(format!("{}/", matched.1))
}

/// Check if ANY MUX case in the response metadata **exactly** matches the DID.
///
/// Uses exact (not floor) matching because this is for cross-service sibling
/// selection where different MUX DOPs can have overlapping ranges.
#[must_use]
pub(super) fn has_mux_case_for_did_exact(meta: &[ResponseParameterInfo], did: u16) -> bool {
    let did_val = u64::from(did);
    meta.iter().any(|p| {
        if let Some(_case_name) = p.name.strip_prefix("__mux_case__/")
            && let cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } = &p.param_type
        {
            return parse_mux_coded_value(coded_value) == Some(did_val);
        }
        false
    })
}

/// Parse numeric literals in decimal or hexadecimal form.
pub(super) fn parse_u64_literal(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    trimmed
        .parse::<u64>()
        .ok()
        .or_else(|| u64::from_str_radix(trimmed, 16).ok())
}

/// Find the DID-bearing parameter by position and type, not by name.
///
/// In standard UDS requests parameters are stored in byte order:
/// - First `CodedConst` whose value matches the SID -> SID indicator (skip)
/// - Next `CodedConst` / `PhysConst` / `Value` -> DID parameter
///
/// This avoids vendor-specific name or semantic string matching.
pub(super) fn find_did_param(
    metadata: &[ServiceParameterMetadata],
    sid: u8,
) -> Option<&ServiceParameterMetadata> {
    let mut skipped_sid = false;
    for p in metadata {
        match &p.param_type {
            cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                if !skipped_sid
                    && let Some(val) = parse_u64_literal(coded_value)
                    && val == u64::from(sid)
                {
                    skipped_sid = true;
                    continue;
                }
                // Non-SID CodedConst -> DID param
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::PhysConst { .. }
            | cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                // PhysConst / Value -> DID param
                return Some(p);
            }
            cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {}
        }
    }
    None
}

/// Check if a DID falls within any `CompuScale` range from the DOP metadata.
///
/// For TEXTTABLE DOPs each scale defines a coded (internal) DID range.
/// Returns `true` if `did` falls in `[lower_limit, upper_limit]` of any scale.
pub(super) fn did_matches_compu_scales(scales: &[CompuScaleInfo], did: u16) -> bool {
    let did_val = u64::from(did);
    scales.iter().any(|s| match (s.lower_limit, s.upper_limit) {
        (Some(lo), Some(hi)) => did_val >= lo && did_val <= hi,
        (Some(lo), None) => did_val == lo,
        _ => false,
    })
}

/// Encode a JSON value into `buf[pos..pos+size]` using big-endian representation.
///
/// Handles numbers, strings, byte arrays, and booleans.  Fills the entire
/// `size` field, zero-padding on the left for numbers shorter than `size`.
pub(super) fn encode_value_at(
    buf: &mut [u8],
    pos: usize,
    size: usize,
    value: Option<&serde_json::Value>,
) {
    let (Some(value), Some(end)) = (
        value,
        pos.checked_add(size)
            .filter(|&e| size > 0 && e <= buf.len()),
    ) else {
        return;
    };

    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            let be = raw.to_be_bytes();
            // Right-align in the field.
            let u64_size = std::mem::size_of::<u64>();
            let start = u64_size.saturating_sub(size);
            let copy = size.min(u64_size);
            // end = pos + size; dst_start = end - copy = pos + (size - copy).
            // copy <= size so no underflow.
            let dst_start = end.saturating_sub(copy);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(dst_start..end),
                be.get(start..start.saturating_add(copy)),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::String(s) => {
            let bytes = s.as_bytes();
            let copy = bytes.len().min(size);
            if let (Some(dst), Some(src)) = (
                buf.get_mut(pos..pos.saturating_add(copy)),
                bytes.get(..copy),
            ) {
                dst.copy_from_slice(src);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                if i >= size {
                    break;
                }
                if let Some(byte) = item.as_u64()
                    && let Some(slot) = buf.get_mut(pos.saturating_add(i))
                {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *slot = byte as u8;
                    }
                }
            }
        }
        serde_json::Value::Bool(b) => {
            if let Some(slot) = buf.get_mut(pos) {
                *slot = u8::from(*b);
            }
        }
        _ => {}
    }
}

/// Serialize a JSON value into raw bytes for UDS encoding.
///
/// Returns an empty Vec when the value is None or cannot be serialized.
pub(super) fn value_to_bytes(value: Option<&serde_json::Value>) -> Vec<u8> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Number(n) => {
            let raw = n
                .as_u64()
                .unwrap_or_else(|| n.as_i64().unwrap_or(0).cast_unsigned());
            encode_unsigned_be(raw)
        }
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                #[allow(clippy::cast_possible_truncation)]
                item.as_u64().map(|b| b as u8)
            })
            .collect(),
        serde_json::Value::Bool(b) => vec![u8::from(*b)],
        _ => Vec::new(),
    }
}

/// Create a [`DiagComm`] for the given service name and UDS service identifier.
///
/// Centralises the repeated inline construction so that callers never have to
/// name [`DiagComm`] directly.  Both `name` and `lookup_name` are set to the
/// same value, which is what the CDA requires for service dispatch.
pub(super) fn make_diag_comm(service_name: &str, service_id: u8) -> DiagComm {
    let name = service_name.to_string();
    DiagComm {
        lookup_name: Some(name.clone()),
        name,
        type_: diag_comm_type(service_id),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::ParameterTypeMetadata;

    use super::*;

    #[test]
    fn test_encode_unsigned_be() {
        assert_eq!(encode_unsigned_be(0), vec![0x00]);
        assert_eq!(encode_unsigned_be(0xFF), vec![0xFF]);
        assert_eq!(encode_unsigned_be(0x0100), vec![0x01, 0x00]);
        assert_eq!(encode_unsigned_be(0xF190), vec![0xF1, 0x90]);
        assert_eq!(encode_unsigned_be(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_unsigned_be(0x01_0000), vec![0x01, 0x00, 0x00]);
        assert_eq!(encode_unsigned_be(0xFF_FFFF), vec![0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encode_unsigned_be(0x0100_0000),
            vec![0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_unsigned_be(0xDEAD_BEEF),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_make_service_payload() {
        let data = &[0x62, 0xF1, 0x90, 0x57];
        let payload = make_service_payload(data);
        assert_eq!(payload.data, vec![0x62, 0xF1, 0x90, 0x57]);
        assert_eq!(payload.source_address, 0);
        assert_eq!(payload.target_address, 0);
        assert!(payload.new_session.is_none());
        assert!(payload.new_security.is_none());
    }

    #[test]
    fn test_parse_mux_coded_value() {
        assert_eq!(parse_mux_coded_value("61699"), Some(61699));
        assert_eq!(parse_mux_coded_value("32776"), Some(32776));
        assert_eq!(parse_mux_coded_value("61699.0"), Some(61699));
        assert_eq!(parse_mux_coded_value(" 61699 "), Some(61699));
        assert_eq!(parse_mux_coded_value("non_numeric_text"), None);
        assert_eq!(parse_mux_coded_value(""), None);
    }

    #[test]
    fn test_find_mux_case_prefix_floor_match() {
        use cda_interfaces::ResponseParameterInfo;

        // Simulate real RDBI_RESP metadata with range-based and point MUX cases.
        let meta = vec![
            // Point case: DID_POINT_8008 covers only DID 0x8008 (32776)
            ResponseParameterInfo {
                name: "__mux_case__/DID_POINT_8008".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "32776".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            // Range case: DID_RANGE_F101_F140 covers 0xF101 (61697) through 0xF140 (61760)
            ResponseParameterInfo {
                name: "__mux_case__/DID_RANGE_F101_F140".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61697".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
            // Point case: DID_POINT_F141 covers only 0xF141 (61761)
            ResponseParameterInfo {
                name: "__mux_case__/DID_POINT_F141".to_string(),
                semantic: Some("MUX-CASE".to_string()),
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "61761".to_string(),
                },
                byte_position: 3,
                bit_position: 0,
                byte_size: None,
            },
        ];

        // Exact match
        assert_eq!(
            find_mux_case_prefix(&meta, 0x8008),
            Some("DID_POINT_8008/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF101),
            Some("DID_RANGE_F101_F140/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF141),
            Some("DID_POINT_F141/".to_string())
        );

        // Floor match within range
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF103), // 61699 -> floor to 61697
            Some("DID_RANGE_F101_F140/".to_string())
        );
        assert_eq!(
            find_mux_case_prefix(&meta, 0xF140), // 61760 -> floor to 61697
            Some("DID_RANGE_F101_F140/".to_string())
        );

        // Float-formatted coded_value
        let meta_float = vec![ResponseParameterInfo {
            name: "__mux_case__/case_a".to_string(),
            semantic: Some("MUX-CASE".to_string()),
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: "61697.0".to_string(),
            },
            byte_position: 3,
            bit_position: 0,
            byte_size: None,
        }];
        assert_eq!(
            find_mux_case_prefix(&meta_float, 0xF103),
            Some("case_a/".to_string())
        );

        // No MUX entries -> None
        assert_eq!(find_mux_case_prefix(&[], 0xF103), None);
    }

    #[test]
    fn test_find_did_param() {
        // Standard RDBI: CodedConst SID + PhysConst DID
        let meta = vec![
            ServiceParameterMetadata {
                name: "RDBI".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(), // 0x22
                },
            },
            ServiceParameterMetadata {
                name: "VIN".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::PhysConst {
                    phys_constant_value: "VIN".to_string(),
                    coded_value: Some(0xF190),
                },
            },
        ];
        let did = find_did_param(&meta, 0x22);
        assert!(did.is_some());
        assert_eq!(did.expect("DID param not found").name, "VIN");

        // Value-type service: SID + Value DID
        let meta2 = vec![
            ServiceParameterMetadata {
                name: "SID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::CodedConst {
                    coded_value: "34".to_string(),
                },
            },
            ServiceParameterMetadata {
                name: "DynamicDID".to_string(),
                semantic: None,
                param_type: ParameterTypeMetadata::Value {
                    physical_default_value: None,
                    coded_default_value: None,
                    compu_scales: vec![],
                },
            },
        ];
        let did = find_did_param(&meta2, 0x22);
        assert!(did.is_some());
        assert!(matches!(
            did.expect("DID param not found").param_type,
            ParameterTypeMetadata::Value { .. }
        ));

        // SID-only service: no DID param
        let meta3 = vec![ServiceParameterMetadata {
            name: "SID".to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: "34".to_string(),
            },
        }];
        assert!(find_did_param(&meta3, 0x22).is_none());
    }
}
