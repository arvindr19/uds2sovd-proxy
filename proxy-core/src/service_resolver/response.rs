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

//! UDS response building and validation.
//!
//! [`ResponseEncoder`] encodes SOVD JSON data into UDS response bytes
//! using MDD parameter metadata.

use cda_interfaces::{
    DiagServiceError, EcuManager as EcuManagerTrait, HashMap, UDS_ID_RESPONSE_BITMASK,
    diagservices::DiagServiceResponse,
};

use super::{
    ManagerHandle, MetadataProvider, UDS_POSITIVE_RESPONSE_MIN_SIZE,
    uds_helpers::{
        encode_unsigned_be, encode_value_at, find_mux_case_prefix, make_diag_comm,
        make_service_payload, value_to_bytes,
    },
};

/// Encodes SOVD JSON data into UDS response bytes using MDD metadata.
pub struct ResponseEncoder {
    manager: ManagerHandle,
    metadata: MetadataProvider,
}

impl ResponseEncoder {
    /// Create a new response encoder.
    pub fn new(manager: ManagerHandle, metadata: MetadataProvider) -> Self {
        Self { manager, metadata }
    }

    /// Build UDS response bytes from SOVD JSON data.
    ///
    /// Queries the MDD POS-RESPONSE layout and encodes each parameter at its
    /// defined byte position:
    ///
    /// - `CODED-CONST` -- fixed value (e.g. response SID).
    /// - `MatchingRequestParam` -- DID bytes echoed from the request.
    /// - `VALUE` -- SOVD data at the MDD offset; defaults to 0 when absent.
    ///
    /// Falls back to naive encoding when no response metadata is available.
    ///
    /// # Errors
    ///
    /// Returns `DiagServiceError` when the response cannot be encoded.
    ///
    /// # TODO
    ///
    /// <https://github.com/eclipse-opensovd/uds2sovd-proxy/issues/17> --
    /// once the SOVD server returns pre-encoded UDS bytes, both encoding
    /// paths can be removed.
    pub async fn build_response(
        &self,
        service_name: &str,
        sid: u8,
        did: u16,
        response_data: HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        tracing::debug!(
            "[MDD] Building UDS response for '{}' SID 0x{:02X} DID 0x{:04X}",
            service_name,
            sid,
            did,
        );

        let (response, effective_service) = if let Some((r, svc)) = self
            .encode_response_from_metadata(service_name, sid, did, &response_data)
            .await
        {
            (r, svc)
        } else {
            // Fallback: naive encoding when no response metadata is available.
            tracing::debug!(
                "[MDD] No response metadata for '{}', using naive encoding",
                service_name
            );
            let response_sid = sid.wrapping_add(UDS_ID_RESPONSE_BITMASK);
            // u16 -> u8 narrowing is safe (each half fits in a byte).
            #[allow(clippy::cast_possible_truncation)]
            let mut response = vec![response_sid, (did >> 8) as u8, (did & 0xFF) as u8];

            let entries: Vec<_> = response_data
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("sid"))
                .collect();

            for (key, value) in entries {
                match value {
                    serde_json::Value::String(s) => {
                        response.extend_from_slice(s.as_bytes());
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(num) = n.as_u64() {
                            response.extend(encode_unsigned_be(num));
                        } else if let Some(num) = n.as_i64() {
                            let unsigned = num.cast_unsigned();
                            #[allow(clippy::cast_possible_truncation)]
                            if u8::try_from(unsigned).is_ok() {
                                response.push(unsigned as u8);
                            } else {
                                response.push((unsigned >> 8) as u8);
                                response.push((unsigned & 0xFF) as u8);
                            }
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            #[allow(clippy::cast_possible_truncation)]
                            if let Some(byte) = item.as_u64() {
                                response.push(byte as u8);
                            }
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        response.push(u8::from(*b));
                    }
                    _ => {
                        tracing::warn!(
                            "[MDD] Skipping unsupported value type for '{}': {:?}",
                            key,
                            value
                        );
                    }
                }
            }

            tracing::debug!("[MDD] Built UDS response (naive): {:02X?}", response);
            (response, service_name.to_string())
        };

        // Debug-only round-trip: parse the built bytes back through the CDA
        // to confirm the MDD layout produces a decodable response.
        if tracing::enabled!(tracing::Level::DEBUG) {
            self.validate_response(&effective_service, sid, &response)
                .await;
        }

        Ok(response)
    }

    /// Encode a UDS response using POS-RESPONSE parameter metadata.
    ///
    /// Returns `None` when no metadata is available. On success returns the
    /// encoded bytes and the effective service name (which may differ when
    /// enriched MUX sibling metadata is used).
    async fn encode_response_from_metadata(
        &self,
        service_name: &str,
        _sid: u8,
        did: u16,
        response_data: &HashMap<String, serde_json::Value>,
    ) -> Option<(Vec<u8>, String)> {
        // Cross-component call: ResponseEncoder -> MetadataProvider.
        let (meta, effective_service) = self
            .metadata
            .get_enriched_response_metadata_with_source(service_name, did)
            .await
            .ok()?;
        if meta.is_empty() {
            return None;
        }

        // Find the MUX case matching this DID (floor-based).
        let mux_case_prefix = find_mux_case_prefix(&meta, did);

        // Derive the case marker name for total_size computation.
        let mux_marker_name: Option<String> = mux_case_prefix
            .as_deref()
            .map(|pfx| format!("__mux_case__/{}", pfx.trim_end_matches('/')));

        // Keep top-level params (no '/') plus matching MUX case sub-params.
        let active_params: Vec<_> = meta
            .iter()
            .filter(|p| {
                if !p.name.contains('/') {
                    true
                } else if let Some(prefix) = &mux_case_prefix {
                    p.name.starts_with(prefix.as_str())
                        || mux_marker_name.as_deref() == Some(&p.name)
                } else {
                    !p.name.starts_with("__mux_case__/")
                }
            })
            .collect();

        // Resolve effective size: for VALUE params with `byte_size: None`
        // (variable-length DOPs), infer the size from actual response data.
        let effective_sizes: Vec<usize> = active_params
            .iter()
            .map(|p| {
                if let Some(s) = p.byte_size {
                    return s as usize;
                }
                // Variable-size VALUE param -- infer size from the data.
                if !matches!(
                    &p.param_type,
                    cda_interfaces::ParameterTypeMetadata::Value { .. }
                ) {
                    return 0;
                }
                let short_name = p.name.rsplit('/').next().unwrap_or(&p.name);
                let value = response_data
                    .get(&p.name)
                    .or_else(|| response_data.get(short_name))
                    .or_else(|| response_data.get(&p.name.to_ascii_lowercase()))
                    .or_else(|| response_data.get(&short_name.to_ascii_lowercase()))
                    .or_else(|| response_data.get("data"));
                value_to_bytes(value).len()
            })
            .collect();

        // Determine total response size from filtered params.
        let total_size = active_params
            .iter()
            .zip(effective_sizes.iter())
            .map(|(p, &sz)| (p.byte_position as usize).saturating_add(sz))
            .max()
            .unwrap_or(UDS_POSITIVE_RESPONSE_MIN_SIZE);

        let mut response = vec![0u8; total_size];

        for (param, &eff_size) in active_params.iter().zip(effective_sizes.iter()) {
            // Skip MUX case markers — they're only used for total_size computation.
            if param.name.starts_with("__mux_case__/") {
                continue;
            }
            let pos = param.byte_position as usize;

            if eff_size == 0 || pos.saturating_add(eff_size) > response.len() {
                continue;
            }

            match &param.param_type {
                cda_interfaces::ParameterTypeMetadata::CodedConst { coded_value } => {
                    // The SID byte is stored as a decimal string (e.g. "98" for 0x62).
                    if let Ok(val) = coded_value.parse::<u64>() {
                        let bytes = encode_unsigned_be(val);
                        let copy_len = bytes.len().min(eff_size);
                        // Right-align in the field (big-endian convention).
                        let offset = eff_size.saturating_sub(copy_len);
                        let dst_start = pos.saturating_add(offset);
                        let dst_end = dst_start.saturating_add(copy_len);
                        let src_start = bytes.len().saturating_sub(copy_len);
                        if let (Some(dst), Some(src)) =
                            (response.get_mut(dst_start..dst_end), bytes.get(src_start..))
                        {
                            dst.copy_from_slice(src);
                        }
                    }
                }
                cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { .. } => {
                    // DID bytes from the original request, big-endian.
                    let did_bytes = [(did >> 8) as u8, (did & 0xFF) as u8];
                    let copy_len = did_bytes.len().min(eff_size);
                    if let (Some(dst), Some(src)) = (
                        response.get_mut(pos..pos.saturating_add(copy_len)),
                        did_bytes.get(..copy_len),
                    ) {
                        dst.copy_from_slice(src);
                    }
                }
                cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                    // For MUX case params, try the short name (after '/') as well.
                    let short_name = param.name.rsplit('/').next().unwrap_or(&param.name);
                    let value = response_data
                        .get(&param.name)
                        .or_else(|| response_data.get(short_name))
                        .or_else(|| response_data.get(&param.name.to_ascii_lowercase()))
                        .or_else(|| response_data.get(&short_name.to_ascii_lowercase()))
                        .or_else(|| response_data.get("data"));

                    if param.byte_size.is_some() {
                        encode_value_at(&mut response, pos, eff_size, value);
                    } else {
                        // Variable-size param: write the raw byte representation.
                        let bytes = value_to_bytes(value);
                        let copy_len = bytes.len().min(eff_size);
                        if let (Some(dst), Some(src)) = (
                            response.get_mut(pos..pos.saturating_add(copy_len)),
                            bytes.get(..copy_len),
                        ) {
                            dst.copy_from_slice(src);
                        }
                    }
                }
                cda_interfaces::ParameterTypeMetadata::PhysConst { .. } => {}
            }
        }

        tracing::debug!(
            "[MDD] Built UDS response via metadata for '{}'): {:02X?}",
            service_name,
            response
        );
        Some((response, effective_service))
    }

    /// Round-trip validate UDS response bytes by parsing them back through
    /// the CDA. Only called at DEBUG level; failures are logged but never
    /// block the response.
    async fn validate_response(&self, service_name: &str, request_sid: u8, uds_response: &[u8]) {
        let diag_comm = make_diag_comm(service_name, request_sid);
        let payload = make_service_payload(uds_response);
        let manager = self.manager.read().await;
        match manager.convert_from_uds(&diag_comm, &payload, true).await {
            Ok(parsed) => match parsed.into_json() {
                Ok(json) => tracing::trace!(
                    "[MDD] Round-trip validation OK for '{}': {:?}",
                    service_name,
                    json.data
                ),
                Err(e) => tracing::warn!(
                    "[MDD] Round-trip validation: JSON decode failed for '{}': {}",
                    service_name,
                    e
                ),
            },
            Err(e) => tracing::warn!(
                "[MDD] Round-trip validation: parse failed for '{}': {}",
                service_name,
                e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{ParameterTypeMetadata, ResponseParameterInfo};

    use super::super::uds_helpers::{
        encode_unsigned_be, encode_value_at, find_mux_case_prefix, value_to_bytes,
    };

    /// Numbers are right-aligned (big-endian) in the target field.
    #[test]
    fn test_encode_value_at_number_right_aligned() {
        let mut buf = [0u8; 5];
        encode_value_at(&mut buf, 1, 2, Some(&serde_json::json!(0xF1_90u64)));
        assert_eq!(buf, [0x00, 0xF1, 0x90, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_value_at_number_single_byte() {
        let mut buf = [0u8; 3];
        encode_value_at(&mut buf, 0, 1, Some(&serde_json::json!(0x62u64)));
        assert_eq!(buf, [0x62, 0x00, 0x00]);
    }

    /// A string value is written left-aligned (byte-for-byte).
    #[test]
    fn test_encode_value_at_string() {
        let mut buf = [0u8; 6];
        encode_value_at(&mut buf, 1, 4, Some(&serde_json::json!("VIN!")));
        assert_eq!(&buf[1..5], b"VIN!");
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[5], 0x00);
    }

    /// A string longer than `size` is truncated.
    #[test]
    fn test_encode_value_at_string_truncated() {
        let mut buf = [0u8; 4];
        encode_value_at(&mut buf, 0, 2, Some(&serde_json::json!("ABCDE")));
        assert_eq!(&buf[..2], b"AB");
        assert_eq!(buf[2], 0x00);
    }

    /// A JSON array encodes each element as one byte.
    #[test]
    fn test_encode_value_at_array() {
        let mut buf = [0u8; 5];
        encode_value_at(
            &mut buf,
            1,
            3,
            Some(&serde_json::json!([0xDEu64, 0xADu64, 0xBEu64])),
        );
        assert_eq!(&buf[1..4], [0xDE, 0xAD, 0xBE]);
    }

    /// `true` encodes as 0x01, `false` as 0x00.
    #[test]
    fn test_encode_value_at_bool() {
        let mut buf = [0u8; 2];
        encode_value_at(&mut buf, 0, 1, Some(&serde_json::json!(true)));
        assert_eq!(buf[0], 0x01);
        encode_value_at(&mut buf, 1, 1, Some(&serde_json::json!(false)));
        assert_eq!(buf[1], 0x00);
    }

    /// `None` leaves the buffer untouched.
    #[test]
    fn test_encode_value_at_none_noop() {
        let mut buf = [0xFFu8; 4];
        encode_value_at(&mut buf, 0, 4, None);
        assert_eq!(buf, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    /// Out-of-bounds write is silently ignored.
    #[test]
    fn test_encode_value_at_out_of_bounds_noop() {
        let mut buf = [0u8; 2];
        // pos=1, size=3 -> end=4 > buf.len()=2 -> noop
        encode_value_at(&mut buf, 1, 3, Some(&serde_json::json!(0xFFu64)));
        assert_eq!(buf, [0x00, 0x00]);
    }

    #[test]
    fn test_value_to_bytes_number() {
        assert_eq!(
            value_to_bytes(Some(&serde_json::json!(0xF190u64))),
            vec![0xF1, 0x90]
        );
    }

    #[test]
    fn test_value_to_bytes_string() {
        assert_eq!(
            value_to_bytes(Some(&serde_json::json!("AB"))),
            b"AB".to_vec()
        );
    }

    #[test]
    fn test_value_to_bytes_array() {
        assert_eq!(
            value_to_bytes(Some(&serde_json::json!([0x01u64, 0x02u64]))),
            vec![0x01, 0x02]
        );
    }

    #[test]
    fn test_value_to_bytes_none() {
        assert_eq!(value_to_bytes(None), Vec::<u8>::new());
    }

    #[test]
    fn test_encode_unsigned_be_zero() {
        assert_eq!(encode_unsigned_be(0), vec![0x00]);
    }

    #[test]
    fn test_encode_unsigned_be_two_bytes() {
        assert_eq!(encode_unsigned_be(0xF190), vec![0xF1, 0x90]);
    }

    /// Build a MUX-case marker `ResponseParameterInfo`.
    fn mux_case_marker(name: &str, lower: u64) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: format!("__mux_case__/{name}"),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: lower.to_string(),
            },
            byte_position: 0,
            bit_position: 0,
            byte_size: None,
        }
    }

    fn value_param(name: &str, pos: u32, size: u32) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::Value {
                physical_default_value: None,
                coded_default_value: None,
                compu_scales: vec![],
            },
            byte_position: pos,
            bit_position: 0,
            byte_size: Some(size),
        }
    }

    fn coded_const_param(name: &str, pos: u32, size: u32, val: &str) -> ResponseParameterInfo {
        ResponseParameterInfo {
            name: name.to_string(),
            semantic: None,
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: val.to_string(),
            },
            byte_position: pos,
            bit_position: 0,
            byte_size: Some(size),
        }
    }

    /// When a MUX case prefix matches the DID, only that case's sub-params
    /// (and the top-level params without '/') are selected; the other case
    /// sub-params are dropped.
    #[test]
    fn test_active_params_with_mux_case() {
        let did: u16 = 0xF190;
        // Sub-params use the case-name prefix (e.g. "VIN/"), NOT "__mux_case__/VIN/".
        let meta = vec![
            coded_const_param("SID", 0, 1, "98"), // top-level, no '/'
            value_param("DID", 1, 2),             // top-level, no '/'
            mux_case_marker("VIN", 0xF190),       // case marker for 0xF190
            mux_case_marker("OTHER", 0xF100),     // different case marker
            value_param("VIN/DATA", 3, 17),       // VIN sub-param
            value_param("OTHER/DATA", 3, 4),      // OTHER sub-param -> excluded
        ];

        let mux_case_prefix = find_mux_case_prefix(&meta, did);
        let mux_marker_name: Option<String> = mux_case_prefix
            .as_deref()
            .map(|pfx| format!("__mux_case__/{}", pfx.trim_end_matches('/')));

        let active: Vec<_> = meta
            .iter()
            .filter(|p| {
                if !p.name.contains('/') {
                    true
                } else if let Some(prefix) = &mux_case_prefix {
                    p.name.starts_with(prefix.as_str())
                        || mux_marker_name.as_deref() == Some(p.name.as_str())
                } else {
                    !p.name.starts_with("__mux_case__/")
                }
            })
            .map(|p| p.name.as_str())
            .collect();

        assert!(active.contains(&"SID"), "top-level SID must be kept");
        assert!(active.contains(&"DID"), "top-level DID must be kept");
        assert!(active.contains(&"VIN/DATA"), "VIN sub-param must be kept");
        assert!(
            !active.contains(&"OTHER/DATA"),
            "OTHER sub-param must be excluded"
        );
    }

    /// Without any MUX case (flat metadata), all params without '/' are kept
    /// and any accidental `__mux_case__` entries are dropped.
    #[test]
    fn test_active_params_no_mux_case() {
        let did: u16 = 0x1234;
        let meta = vec![
            coded_const_param("SID", 0, 1, "98"),
            value_param("DATA", 3, 4),
        ];

        let mux_case_prefix = find_mux_case_prefix(&meta, did);
        assert!(mux_case_prefix.is_none());

        let active: Vec<_> = meta
            .iter()
            .filter(|p| !p.name.contains('/') || p.name.starts_with("__mux_case__/"))
            .map(|p| p.name.as_str())
            .collect();

        assert_eq!(active, ["SID", "DATA"]);
    }

    /// `total_size` is the maximum of (`byte_position` + `effective_size`) across params.
    #[test]
    fn test_total_size_from_params() {
        let params = vec![
            coded_const_param("SID", 0, 1, "98"),
            value_param("DID", 1, 2),
            value_param("DATA", 3, 17),
        ];
        let effective_sizes: Vec<usize> = params
            .iter()
            .map(|p| p.byte_size.map_or(0, |s| s as usize))
            .collect();

        let total = params
            .iter()
            .zip(effective_sizes.iter())
            .map(|(p, &sz)| (p.byte_position as usize).saturating_add(sz))
            .max()
            .unwrap_or(3);

        // SID: 0+1=1, DID: 1+2=3, DATA: 3+17=20 -> max = 20
        assert_eq!(total, 20);
    }
}
