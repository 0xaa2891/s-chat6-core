//! Circumvention config applied as a `SETCONF` batch.
//!
//! Options are applied over the control port rather than by rewriting
//! the torrc and restarting the process. The
//! `pt_available` flag carries the honest "no PT binary" warning state so a
//! client can show it (IPtProxy wiring is a client task).

use super::error::TransportError;

pub const MAX_BRIDGES: usize = 24;
pub const MAX_BRIDGE_LINE_CHARS: usize = 512;

const PT_TYPES: [&str; 8] = [
    "obfs4",
    "obfs3",
    "scramblesuit",
    "meek",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "conjure",
];

/// Control-port keys this module manages (used for RESETCONF on clear).
pub const MANAGED_KEYS: [&str; 6] = [
    "UseBridges",
    "Bridge",
    "FascistFirewall",
    "ClientPreferIPv6ORPort",
    "ClientUseIPv4",
    "ClientUseIPv6",
];

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct CircumventionConfig {
    pub use_bridges: bool,
    pub bridges: Vec<String>,
    pub fascist_firewall: bool,
    pub prefer_ipv6: bool,
    pub use_ipv4: bool,
    pub use_ipv6: bool,
    /// False when the client has no pluggable-transport binary — PT bridge
    /// lines then trigger the honest warning instead of silent failure.
    pub pt_available: bool,
}

impl CircumventionConfig {
    /// Decode clamp: IPv4 and IPv6 cannot both be disabled.
    pub fn normalized(mut self) -> Self {
        if !self.use_ipv4 && !self.use_ipv6 {
            self.use_ipv4 = true;
            self.use_ipv6 = true;
        }
        self
    }

    /// Parse bridge lines: strip `#` comments, optional `Bridge ` prefix,
    /// max 24 lines × 512 chars.
    pub fn parse_bridges(text: &str) -> Vec<String> {
        text.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.strip_prefix("Bridge ").unwrap_or(l).trim().to_string())
            .filter(|l| !l.is_empty() && l.chars().count() <= MAX_BRIDGE_LINE_CHARS)
            .take(MAX_BRIDGES)
            .collect()
    }

    pub fn looks_like_pluggable_transport(bridge: &str) -> bool {
        let first = bridge.split_whitespace().next().unwrap_or_default();
        PT_TYPES.contains(&first)
    }

    pub fn uses_pluggable_transport(&self) -> bool {
        self.bridges
            .iter()
            .any(|b| Self::looks_like_pluggable_transport(b))
    }

    /// The honest warning: PT bridges configured but no
    /// PT binary available in this build.
    pub fn pt_warning(&self) -> Option<String> {
        if self.use_bridges && self.uses_pluggable_transport() && !self.pt_available {
            Some(
                "bridge lines name a pluggable transport, but this build has no PT binary; \
                 only vanilla IP:port bridges will work"
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// The `SETCONF` batch applying this config:
    /// FascistFirewall, ClientPreferIPv6ORPort,
    /// ClientUseIPv4/6, UseBridges + Bridge lines.
    pub fn setconf_pairs(&self) -> Vec<(String, String)> {
        let cfg = self.clone().normalized();
        let mut pairs = Vec::new();
        pairs.push((
            "FascistFirewall".into(),
            if cfg.fascist_firewall { "1" } else { "0" }.into(),
        ));
        pairs.push((
            "ClientPreferIPv6ORPort".into(),
            if cfg.prefer_ipv6 { "1" } else { "0" }.into(),
        ));
        pairs.push((
            "ClientUseIPv4".into(),
            if cfg.use_ipv4 { "1" } else { "0" }.into(),
        ));
        pairs.push((
            "ClientUseIPv6".into(),
            if cfg.use_ipv6 { "1" } else { "0" }.into(),
        ));
        if cfg.use_bridges && !cfg.bridges.is_empty() {
            pairs.push(("UseBridges".into(), "1".into()));
            for b in &cfg.bridges {
                pairs.push(("Bridge".into(), b.clone()));
            }
        } else {
            pairs.push(("UseBridges".into(), "0".into()));
        }
        pairs
    }

    pub fn validate(&self) -> Result<(), TransportError> {
        if self.bridges.len() > MAX_BRIDGES {
            return Err(TransportError::Control(format!(
                "too many bridges: {} > {MAX_BRIDGES}",
                self.bridges.len()
            )));
        }
        for b in &self.bridges {
            if b.chars().count() > MAX_BRIDGE_LINE_CHARS {
                return Err(TransportError::Control("bridge line too long".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setconf_batch_matches_torrc_lines() {
        let cfg = CircumventionConfig {
            use_bridges: true,
            bridges: vec!["1.2.3.4:443 AAAA".into()],
            fascist_firewall: true,
            prefer_ipv6: true,
            use_ipv4: false,
            use_ipv6: true,
            pt_available: false,
        };
        let pairs = cfg.setconf_pairs();
        assert!(pairs.contains(&("FascistFirewall".into(), "1".into())));
        assert!(pairs.contains(&("ClientPreferIPv6ORPort".into(), "1".into())));
        assert!(pairs.contains(&("ClientUseIPv4".into(), "0".into())));
        assert!(pairs.contains(&("ClientUseIPv6".into(), "1".into())));
        assert!(pairs.contains(&("UseBridges".into(), "1".into())));
        assert!(pairs.contains(&("Bridge".into(), "1.2.3.4:443 AAAA".into())));
    }

    #[test]
    fn cannot_disable_both_ip_versions() {
        let cfg = CircumventionConfig {
            use_ipv4: false,
            use_ipv6: false,
            ..Default::default()
        }
        .normalized();
        assert!(cfg.use_ipv4 && cfg.use_ipv6);
    }

    #[test]
    fn bridge_parsing_limits_and_prefix() {
        let text = "# comment\nBridge 1.2.3.4:443\n\nobfs4 5.6.7.8:443 cert=x\n";
        let bridges = CircumventionConfig::parse_bridges(text);
        assert_eq!(bridges, vec!["1.2.3.4:443", "obfs4 5.6.7.8:443 cert=x"]);

        let many = (0..30)
            .map(|i| format!("10.0.0.{i}:443"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(CircumventionConfig::parse_bridges(&many).len(), MAX_BRIDGES);

        let long = format!("{}\n", "a".repeat(600));
        assert!(CircumventionConfig::parse_bridges(&long).is_empty());
    }

    #[test]
    fn pt_detection_and_warning() {
        assert!(CircumventionConfig::looks_like_pluggable_transport(
            "obfs4 1.2.3.4:443 cert=abc"
        ));
        assert!(CircumventionConfig::looks_like_pluggable_transport(
            "snowflake 0.0.3.0:1"
        ));
        assert!(!CircumventionConfig::looks_like_pluggable_transport(
            "1.2.3.4:443 AABBCC"
        ));

        let cfg = CircumventionConfig {
            use_bridges: true,
            bridges: vec!["obfs4 1.2.3.4:443 cert=abc".into()],
            pt_available: false,
            ..Default::default()
        };
        assert!(cfg.pt_warning().is_some());
        let with_pt = CircumventionConfig {
            pt_available: true,
            ..cfg.clone()
        };
        assert!(with_pt.pt_warning().is_none());
        let vanilla = CircumventionConfig {
            bridges: vec!["1.2.3.4:443".into()],
            ..cfg
        };
        assert!(vanilla.pt_warning().is_none());
    }
}
