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

/// `DoIP` routing activation session state.
///
/// Tracks whether a valid routing activation exchange has occurred
/// and stores the source address of the activated tester.
pub struct Session {
    /// `true` after a successful routing activation response.
    routing_activated: bool,
    /// Source address of the activated tester, if any.
    source_address: Option<u16>,
}

impl Session {
    /// Create a new inactive session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routing_activated: false,
            source_address: None,
        }
    }

    /// Activate the session with the given tester source address.
    pub fn activate(&mut self, source_address: u16) {
        self.routing_activated = true;
        self.source_address = Some(source_address);
    }

    /// Returns `true` if routing activation has been completed.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        self.routing_activated
    }

    /// Returns `true` if the session is activated for the given source address.
    #[must_use]
    pub fn is_activated_for(&self, source_address: u16) -> bool {
        self.routing_activated && self.source_address == Some(source_address)
    }

    /// Returns the tester source address, if activated.
    #[must_use]
    pub fn source_address(&self) -> Option<u16> {
        self.source_address
    }

    /// Reset the session to an inactive state.
    pub fn clear(&mut self) {
        self.routing_activated = false;
        self.source_address = None;
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session_inactive() {
        let session = Session::new();
        assert!(!session.is_activated());
        assert_eq!(session.source_address(), None);
    }

    #[test]
    fn test_session_activation_for_source() {
        let mut session = Session::new();
        session.activate(0x0E80);

        assert!(session.is_activated());
        assert!(session.is_activated_for(0x0E80));
        assert!(!session.is_activated_for(0x0E81));
    }

    #[test]
    fn test_session_clear() {
        let mut session = Session::new();
        session.activate(0x0E80);
        session.clear();

        assert!(!session.is_activated());
        assert_eq!(session.source_address(), None);
    }
}
