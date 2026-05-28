//! Threshold-based decision policy.
//!
//! Maps a `RiskScore` to a `Decision` using configurable thresholds
//! that vary by trust mode. The policy is config-driven — adding a
//! new trust mode is adding a config entry, not an `if/else` chain.

use crate::config::{DecisionThresholds, TrustModeConfig};
use crate::traits::DecisionPolicy;
use crate::types::{Decision, RiskScore, TrustMode};

/// Default decision policy using threshold ranges.
///
/// Score-to-decision mapping (default thresholds):
/// - `0–4` → Allow
/// - `5–9` → Warn
/// - `10–14` → Block
/// - `15–20` → Critical (always enforced)
///
/// # Design
/// - Swappable via the `DecisionPolicy` trait.
/// - Config-driven: Thresholds come from `TrustModeConfig`, not code.
/// - Pure function: No I/O, no state.
#[derive(Debug, Default)]
pub struct ThresholdDecisionPolicy {
    /// Base thresholds (from `ScoringConfig`).
    thresholds: DecisionThresholds,
}

impl ThresholdDecisionPolicy {
    /// Creates a new policy with the given base thresholds.
    pub fn new(thresholds: DecisionThresholds) -> Self {
        Self { thresholds }
    }

    /// Resolves the effective thresholds for a trust mode.
    ///
    /// Returns `(allow_max, block_min)` where:
    /// - Scores `0..=allow_max` → Allow
    /// - Scores `allow_max+1..=block_min-1` → Warn
    /// - Scores `block_min..=14` → Block
    /// - Scores `15..=20` → Critical (always enforced)
    fn effective_thresholds(&self, mode_config: &TrustModeConfig) -> (u8, u8) {
        // warn_threshold_override replaces allow_max:
        // "start warning at scores above this value"
        let allow_max = mode_config
            .warn_threshold_override
            .unwrap_or(self.thresholds.allow_max);

        // block_threshold_override replaces the warn/block boundary:
        // "start blocking at scores above this value"
        let block_min = mode_config
            .block_threshold_override
            .map(|v| v + 1)
            .unwrap_or(self.thresholds.warn_max + 1);

        (allow_max, block_min)
    }
}

impl DecisionPolicy for ThresholdDecisionPolicy {
    fn decide(&self, score: RiskScore, _mode: TrustMode, config: &TrustModeConfig) -> Decision {
        let value = score.value();
        let (allow_max, block_min) = self.effective_thresholds(config);

        // Critical is always enforced regardless of mode (score ≥ 15)
        if value >= 15 {
            return Decision::Critical {
                reasons: vec![format!(
                    "risk score {value}/20 exceeds critical threshold (15)"
                )],
            };
        }

        // Block: score at or above the block boundary
        if value >= block_min {
            return Decision::Block {
                reasons: vec![format!("risk score {value}/20 exceeds block threshold")],
            };
        }

        // Warn: score exceeds the allow threshold
        if value > allow_max {
            return Decision::Warn {
                reasons: vec![format!(
                    "risk score {value}/20 exceeds warn threshold ({allow_max})"
                )],
            };
        }

        // Allow: score within the allow range
        Decision::Allow
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn balanced_config() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: true,
            warn_threshold_override: None,
            block_threshold_override: None,
        }
    }

    fn paranoid_config() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: false,
            warn_threshold_override: Some(0),
            block_threshold_override: Some(0),
        }
    }

    fn yolo_config() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: true,
            warn_threshold_override: Some(14),
            block_threshold_override: Some(14),
        }
    }

    fn default_policy() -> ThresholdDecisionPolicy {
        ThresholdDecisionPolicy::new(DecisionThresholds::default())
    }

    // --- Balanced mode tests ---

    #[test]
    fn allow_low_score_balanced() {
        let policy = default_policy();
        let decision = policy.decide(RiskScore::new(3), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn allow_at_boundary_balanced() {
        let policy = default_policy();
        // Score 4 = allow_max → still Allow
        let decision = policy.decide(RiskScore::new(4), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn warn_medium_score_balanced() {
        let policy = default_policy();
        // Score 7 is in warn range (5–9)
        let decision = policy.decide(RiskScore::new(7), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Warn { .. }));
    }

    #[test]
    fn warn_at_boundary_balanced() {
        let policy = default_policy();
        // Score 5 = allow_max+1 → first warn
        let decision = policy.decide(RiskScore::new(5), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Warn { .. }));
    }

    #[test]
    fn block_high_score_balanced() {
        let policy = default_policy();
        // Score 12 is in block range (10–14)
        let decision = policy.decide(RiskScore::new(12), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn block_at_boundary_balanced() {
        let policy = default_policy();
        // Score 10 = block_min → first block
        let decision = policy.decide(RiskScore::new(10), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn critical_very_high_score() {
        let policy = default_policy();
        let decision = policy.decide(RiskScore::new(17), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Critical { .. }));
    }

    #[test]
    fn critical_at_boundary() {
        let policy = default_policy();
        // Score 15 is the critical boundary
        let decision = policy.decide(RiskScore::new(15), TrustMode::Balanced, &balanced_config());
        assert!(matches!(decision, Decision::Critical { .. }));
    }

    // --- Paranoid mode tests ---

    #[test]
    fn paranoid_blocks_low_scores() {
        let policy = default_policy();
        // Paranoid: allow_max=0, block_min=1 → score 2 is Block
        let decision = policy.decide(RiskScore::new(2), TrustMode::Paranoid, &paranoid_config());
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn paranoid_blocks_score_one() {
        let policy = default_policy();
        // Score 1 = block_min → Block
        let decision = policy.decide(RiskScore::new(1), TrustMode::Paranoid, &paranoid_config());
        assert!(matches!(decision, Decision::Block { .. }));
    }

    #[test]
    fn paranoid_allows_zero() {
        let policy = default_policy();
        // Score 0 ≤ allow_max(0) → Allow
        let decision = policy.decide(RiskScore::new(0), TrustMode::Paranoid, &paranoid_config());
        assert!(matches!(decision, Decision::Allow));
    }

    // --- YOLO mode tests ---

    #[test]
    fn yolo_allows_high_scores() {
        let policy = default_policy();
        // YOLO: allow_max=14, so score 12 is Allow
        let decision = policy.decide(RiskScore::new(12), TrustMode::Yolo, &yolo_config());
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn yolo_still_blocks_critical() {
        let policy = default_policy();
        // Critical threshold (15) is enforced in all modes
        let decision = policy.decide(RiskScore::new(16), TrustMode::Yolo, &yolo_config());
        assert!(matches!(decision, Decision::Critical { .. }));
    }

    // --- Decision content tests ---

    #[test]
    fn decision_contains_score_in_reason() {
        let policy = default_policy();
        let decision = policy.decide(RiskScore::new(7), TrustMode::Balanced, &balanced_config());
        if let Decision::Warn { reasons } = decision {
            assert!(reasons[0].contains("7/20"));
        } else {
            panic!("expected Warn decision for score 7");
        }
    }
}
