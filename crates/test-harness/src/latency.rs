//! Hot-path latency measurement and regression budgets.
//!
//! "Hot": `TransportStatus.tor == Online`, the
//! per-relationship service `Reachable`, and a SOCKS stream to the peer
//! still inside the 60 s post-send reuse window (`CONVERSATION_HOLD`).
//! The harness guarantees the third leg by construction (samples are
//! sent back-to-back, each far under 60 s after the previous) and
//! records a violation if a sample ever finds the first two legs unmet.
//!
//! Budgets live in `tools/reliability/latency-budgets.json` (override
//! with `SCHAT_LATENCY_BUDGETS`). A scenario run fails when its
//! percentiles exceed the gate values, or — once a baseline entry
//! exists — when they regress by more than `regression_tolerance_pct`
//! against it. On the first run for a scenario the measured percentiles
//! are written back as the baseline.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One measured latency series (milliseconds).
#[derive(Clone, Debug, Default)]
pub struct LatencySeries {
    pub name: String,
    pub samples_ms: Vec<f64>,
}

impl LatencySeries {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            samples_ms: Vec::new(),
        }
    }

    pub fn record(&mut self, d: Duration) {
        self.samples_ms.push(d.as_secs_f64() * 1000.0);
    }

    pub fn percentiles(&self) -> Percentiles {
        percentiles(&self.samples_ms)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    pub count: u32,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

/// Nearest-rank percentiles over the sample set.
pub fn percentiles(samples: &[f64]) -> Percentiles {
    if samples.is_empty() {
        return Percentiles::default();
    }
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    let rank = |p: f64| {
        let idx = (p / 100.0 * n as f64).ceil() as usize;
        s[idx.clamp(1, n) - 1]
    };
    Percentiles {
        count: n as u32,
        min_ms: s[0],
        p50_ms: rank(50.0),
        p95_ms: rank(95.0),
        p99_ms: rank(99.0),
        max_ms: s[n - 1],
        mean_ms: s.iter().sum::<f64>() / n as f64,
    }
}

/// The hard gate for one scenario (any percentile may be omitted).
#[derive(Clone, Debug, Default)]
pub struct Budget {
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

/// The parsed budgets file, plus its raw JSON for baseline write-back.
pub struct Budgets {
    pub gates: BTreeMap<String, Budget>,
    pub regression_tolerance_pct: f64,
    pub baseline: BTreeMap<String, Percentiles>,
    raw: serde_json::Map<String, serde_json::Value>,
    path: PathBuf,
}

/// `<workspace>/tools/reliability/latency-budgets.json`, overridable via
/// `SCHAT_LATENCY_BUDGETS` (dev runs point at a throwaway copy so they
/// don't pollute the checked-in baseline).
pub fn budgets_path() -> PathBuf {
    std::env::var_os("SCHAT_LATENCY_BUDGETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/reliability/latency-budgets.json")
        })
}

impl Budgets {
    pub fn load(path: &Path) -> Result<Self, String> {
        let body =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let raw: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let mut gates = BTreeMap::new();
        let mut baseline = BTreeMap::new();
        let mut tolerance = 10.0;
        for (key, value) in &raw {
            match key.as_str() {
                "regression_tolerance_pct" => {
                    tolerance = value
                        .as_f64()
                        .ok_or("regression_tolerance_pct must be a number")?;
                }
                "baseline" => {
                    let obj = value.as_object().ok_or("baseline must be an object")?;
                    for (scenario, pct) in obj {
                        let p: Percentiles = serde_json::from_value(pct.clone())
                            .map_err(|e| format!("baseline.{scenario}: {e}"))?;
                        baseline.insert(scenario.clone(), p);
                    }
                }
                scenario => {
                    let obj = value
                        .as_object()
                        .ok_or_else(|| format!("{scenario}: budget must be an object"))?;
                    let get = |k: &str| obj.get(k).and_then(|v| v.as_f64());
                    gates.insert(
                        scenario.to_string(),
                        Budget {
                            p50_ms: get("p50_ms"),
                            p95_ms: get("p95_ms"),
                            p99_ms: get("p99_ms"),
                        },
                    );
                }
            }
        }
        Ok(Self {
            gates,
            regression_tolerance_pct: tolerance,
            baseline,
            raw,
            path: path.to_path_buf(),
        })
    }

    /// Every budget/regression violation for one measured series.
    /// Empty = pass.
    pub fn violations(&self, scenario: &str, measured: &Percentiles) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(gate) = self.gates.get(scenario) {
            for (name, limit, got) in [
                ("p50", gate.p50_ms, measured.p50_ms),
                ("p95", gate.p95_ms, measured.p95_ms),
                ("p99", gate.p99_ms, measured.p99_ms),
            ] {
                if let Some(limit) = limit {
                    if got > limit {
                        out.push(format!(
                            "{scenario} {name} {got:.0}ms exceeds budget {limit:.0}ms"
                        ));
                    }
                }
            }
        }
        if let Some(base) = self.baseline.get(scenario) {
            let factor = 1.0 + self.regression_tolerance_pct / 100.0;
            for (name, was, got) in [
                ("p50", base.p50_ms, measured.p50_ms),
                ("p95", base.p95_ms, measured.p95_ms),
                ("p99", base.p99_ms, measured.p99_ms),
            ] {
                if was > 0.0 && got > was * factor {
                    out.push(format!(
                        "{scenario} {name} {got:.0}ms regresses >{:.0}% vs baseline {was:.0}ms",
                        self.regression_tolerance_pct
                    ));
                }
            }
        }
        out
    }

    /// First run for a scenario: record the measured percentiles as the
    /// baseline and write the budgets file back. Returns true when the
    /// file was updated.
    pub fn ensure_baseline(
        &mut self,
        scenario: &str,
        measured: &Percentiles,
    ) -> Result<bool, String> {
        if self.baseline.contains_key(scenario) {
            return Ok(false);
        }
        let value = serde_json::to_value(measured).map_err(|e| e.to_string())?;
        self.raw
            .entry("baseline")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or("baseline is not an object")?
            .insert(scenario.to_string(), value);
        let body = serde_json::to_string_pretty(&serde_json::Value::Object(self.raw.clone()))
            .map_err(|e| e.to_string())?;
        std::fs::write(&self.path, body)
            .map_err(|e| format!("write {}: {e}", self.path.display()))?;
        self.baseline.insert(scenario.to_string(), *measured);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_nearest_rank() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = percentiles(&samples);
        assert_eq!(p.count, 100);
        assert_eq!(p.p50_ms, 50.0);
        assert_eq!(p.p95_ms, 95.0);
        assert_eq!(p.p99_ms, 99.0);
        assert_eq!(p.min_ms, 1.0);
        assert_eq!(p.max_ms, 100.0);
    }

    #[test]
    fn violations_gate_and_regression() {
        let mut raw = serde_json::Map::new();
        raw.insert(
            "msg_hot".into(),
            serde_json::json!({"p50_ms": 3000, "p95_ms": 8000, "p99_ms": 15000}),
        );
        raw.insert("regression_tolerance_pct".into(), serde_json::json!(10));
        raw.insert(
            "baseline".into(),
            serde_json::json!({"msg_hot": {"count": 200, "min_ms": 100.0, "p50_ms": 1000.0,
                "p95_ms": 2000.0, "p99_ms": 4000.0, "max_ms": 5000.0, "mean_ms": 900.0}}),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budgets.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::Value::Object(raw)).unwrap(),
        )
        .unwrap();
        let mut budgets = Budgets::load(&path).unwrap();

        // Within gate and within 10% of baseline: pass.
        let ok = Percentiles {
            count: 200,
            p50_ms: 1050.0,
            p95_ms: 2100.0,
            p99_ms: 4100.0,
            ..Default::default()
        };
        assert!(budgets.violations("msg_hot", &ok).is_empty());

        // Over the gate: fail.
        let over_gate = Percentiles {
            p95_ms: 9000.0,
            ..ok
        };
        assert!(budgets
            .violations("msg_hot", &over_gate)
            .iter()
            .any(|v| v.contains("exceeds budget")));

        // Over baseline +10% but under the gate: regression fail.
        let regressed = Percentiles {
            p50_ms: 1150.0,
            ..ok
        };
        assert!(budgets
            .violations("msg_hot", &regressed)
            .iter()
            .any(|v| v.contains("regresses")));

        // Unknown scenario: no gate, no baseline; ensure_baseline writes it.
        assert!(budgets.violations("new_scenario", &ok).is_empty());
        assert!(budgets.ensure_baseline("new_scenario", &ok).unwrap());
        assert!(!budgets.ensure_baseline("new_scenario", &ok).unwrap());
        let reloaded = Budgets::load(&path).unwrap();
        assert!(reloaded.baseline.contains_key("new_scenario"));
    }
}
