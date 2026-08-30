//! Self-heal ladder and bounded restarts.
//!
//! Ladder: RELOAD → NEWNYM → daemon restart, with per-rung cooldowns
//! (60 s / 120 s / 300 s). Every trigger is logged with its reason by the
//! caller — no silent restarts. Restarts are **bounded**: more than
//! [`MAX_RESTARTS`] inside `RESTART_WINDOW` surfaces `Dead` and healing
//! stops.

use std::collections::VecDeque;

pub const HEAL_RELOAD_COOLDOWN_MS: u64 = 60_000;
pub const HEAL_NEWNYM_COOLDOWN_MS: u64 = 120_000;
pub const HEAL_RESTART_COOLDOWN_MS: u64 = 300_000;

pub const MAX_RESTARTS: usize = 3;
pub const RESTART_WINDOW_MS: u64 = 10 * 60_000;

/// Trigger thresholds.
pub const HEAL_CONNECT_FAILS: u32 = 6;
pub const HS_WINDOW_MS: u64 = 900_000;
pub const HS_FAIL_MIN: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealAction {
    Reload,
    Newnym,
    Restart,
}

/// The ladder itself, with an injectable clock (ms) for tests.
pub struct HealLadder {
    level: u32,
    last_heal_ms: Option<u64>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl HealLadder {
    pub fn new(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            level: 0,
            last_heal_ms: None,
            now: Box::new(now),
        }
    }

    pub fn system() -> Self {
        Self::new(super::status::now_millis)
    }

    pub fn level(&self) -> u32 {
        self.level
    }

    /// Escalate one rung. Returns `None` when the current rung is still in
    /// its cooldown (the heal attempt is skipped entirely).
    pub fn escalate(&mut self) -> Option<HealAction> {
        let now = (self.now)();
        let cooldown = match self.level {
            0 => 0,
            1 => HEAL_RELOAD_COOLDOWN_MS,
            2 => HEAL_NEWNYM_COOLDOWN_MS,
            _ => HEAL_RESTART_COOLDOWN_MS,
        };
        if let Some(last) = self.last_heal_ms {
            if now.saturating_sub(last) < cooldown {
                return None;
            }
        }
        self.last_heal_ms = Some(now);
        let action = match self.level {
            0 => HealAction::Reload,
            1 => HealAction::Newnym,
            _ => HealAction::Restart,
        };
        self.level += 1;
        Some(action)
    }

    /// Healthy window observed (no failures and at least one upload
    /// resets the ladder).
    pub fn reset(&mut self) {
        self.level = 0;
    }
}

/// Bounded daemon restarts: after [`MAX_RESTARTS`] within
/// [`RESTART_WINDOW_MS`], the daemon is declared dead and healing stops.
pub struct RestartBudget {
    restarts: VecDeque<u64>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl RestartBudget {
    pub fn new(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            restarts: VecDeque::new(),
            now: Box::new(now),
        }
    }

    pub fn system() -> Self {
        Self::new(super::status::now_millis)
    }

    /// Record a restart attempt. `false` = budget exhausted → surface `Dead`.
    pub fn record_restart(&mut self) -> bool {
        let now = (self.now)();
        while self
            .restarts
            .front()
            .is_some_and(|t| now.saturating_sub(*t) > RESTART_WINDOW_MS)
        {
            self.restarts.pop_front();
        }
        if self.restarts.len() >= MAX_RESTARTS {
            return false;
        }
        self.restarts.push_back(now);
        true
    }
}

/// HS_DESC health window: within 15 min, `FAILED` count ≥ 3 and
/// failures > uploads → escalate. A clean window with uploads resets the
/// ladder.
#[derive(Default)]
pub struct HsHealth {
    pub failures: u32,
    pub uploads: u32,
}

impl HsHealth {
    pub fn record_failed(&mut self) {
        self.failures += 1;
    }

    pub fn record_uploaded(&mut self) {
        self.uploads += 1;
    }

    /// End-of-window evaluation: (escalate?, reset_ladder?)
    pub fn evaluate(&self) -> (bool, bool) {
        let escalate = self.failures >= HS_FAIL_MIN && self.failures > self.uploads;
        let healthy = self.failures == 0 && self.uploads > 0;
        (escalate, healthy)
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn fake_clock() -> (Arc<Mutex<u64>>, impl Fn() -> u64 + Send + Sync + 'static) {
        let t = Arc::new(Mutex::new(0u64));
        let t2 = t.clone();
        (t, move || *t2.lock().unwrap())
    }

    #[test]
    fn ladder_escalates_with_cooldowns() {
        let (t, now) = fake_clock();
        let mut ladder = HealLadder::new(now);
        assert_eq!(ladder.escalate(), Some(HealAction::Reload));
        // Rung 1 cooldown: 60 s before NEWNYM can fire.
        assert_eq!(ladder.escalate(), None);
        *t.lock().unwrap() = 59_999;
        assert_eq!(ladder.escalate(), None);
        *t.lock().unwrap() = 60_000;
        assert_eq!(ladder.escalate(), Some(HealAction::Newnym));
        // Rung 2 cooldown: 120 s before Restart.
        *t.lock().unwrap() = 60_000 + 119_999;
        assert_eq!(ladder.escalate(), None);
        *t.lock().unwrap() = 60_000 + 120_000;
        assert_eq!(ladder.escalate(), Some(HealAction::Restart));
        // Rung 3 cooldown: 300 s.
        *t.lock().unwrap() = 180_000 + 299_999;
        assert_eq!(ladder.escalate(), None);
        *t.lock().unwrap() = 180_000 + 300_000;
        assert_eq!(ladder.escalate(), Some(HealAction::Restart));
    }

    #[test]
    fn ladder_resets_on_healthy_window() {
        let (t, now) = fake_clock();
        let mut ladder = HealLadder::new(now);
        ladder.escalate();
        ladder.escalate();
        ladder.reset();
        *t.lock().unwrap() = 1;
        assert_eq!(ladder.escalate(), Some(HealAction::Reload));
    }

    #[test]
    fn restart_budget_bounds_healing() {
        let (t, now) = fake_clock();
        let mut budget = RestartBudget::new(now);
        assert!(budget.record_restart());
        assert!(budget.record_restart());
        assert!(budget.record_restart());
        assert!(!budget.record_restart()); // 4th in window → dead
                                           // After the window slides, restarts are allowed again.
        *t.lock().unwrap() = RESTART_WINDOW_MS + 1;
        assert!(budget.record_restart());
    }

    #[test]
    fn hs_health_window() {
        let mut h = HsHealth::default();
        h.record_uploaded();
        assert_eq!(h.evaluate(), (false, true));
        h.clear();
        h.record_failed();
        h.record_failed();
        assert_eq!(h.evaluate(), (false, false)); // below HS_FAIL_MIN
        h.record_failed();
        assert_eq!(h.evaluate(), (true, false));
        h.record_uploaded();
        h.record_uploaded();
        h.record_uploaded();
        h.record_uploaded();
        assert_eq!(h.evaluate(), (false, false)); // uploads >= failures
    }
}
