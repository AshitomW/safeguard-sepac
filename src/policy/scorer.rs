//! Weighted additive risk scorer.
//!
//! The scorer is a pure function: it receives signals and config,
//! and returns a bounded `RiskScore`. It never reads from the filesystem
//! or network. Weights are loaded from config at startup.

use crate::config::ScoringConfig;
use crate::traits::Scorer;
use crate::types::{RiskScore, Signal};

/// Default scorer using a weighted additive model.
///
/// For each signal, the scorer looks up the weight by signal label in
/// `ScoringConfig::weights`. Unknown signal labels receive a weight of 0.
/// The sum is capped at `ScoringConfig::max_score`.
///
/// # Design
/// - Swappable via the `Scorer` trait.
/// - Pure function: No I/O, no side effects.
/// - Config-driven: Weights live in TOML, never hardcoded here.
#[derive(Debug, Default)]
pub struct WeightedAdditiveScorer;

impl WeightedAdditiveScorer {
    /// Creates a new weighted additive scorer.
    pub fn new() -> Self {
        Self
    }
}

impl Scorer for WeightedAdditiveScorer {
    fn score(&self, signals: &[Signal], config: &ScoringConfig) -> RiskScore {
        let raw_sum: f64 = signals
            .iter()
            .map(|signal| {
                let label = signal.label();
                config.weights.get(label).copied().unwrap_or(0.0)
            })
            .sum();

        let capped = (raw_sum.round() as u8).min(config.max_score);
        RiskScore::new(capped)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn default_config() -> ScoringConfig {
        ScoringConfig::default()
    }

    #[test]
    fn no_signals_yields_zero() {
        let scorer = WeightedAdditiveScorer::new();
        let score = scorer.score(&[], &default_config());
        assert_eq!(score.value(), 0);
    }

    #[test]
    fn single_signal_uses_configured_weight() {
        let scorer = WeightedAdditiveScorer::new();
        let signals = vec![Signal::PostInstallAdded {
            previous_versions_without: 100,
        }];
        let config = default_config();
        let score = scorer.score(&signals, &config);
        // Default weight for post-install-added is 5.0
        assert_eq!(score.value(), 5);
    }

    #[test]
    fn multiple_signals_sum() {
        let scorer = WeightedAdditiveScorer::new();
        let signals = vec![
            Signal::PostInstallAdded {
                previous_versions_without: 100,
            },
            Signal::NewMaintainer {
                account_age_days: 2,
            },
        ];
        let config = default_config();
        let score = scorer.score(&signals, &config);
        // 5.0 + 3.0 = 8.0
        assert_eq!(score.value(), 8);
    }

    #[test]
    fn score_caps_at_max() {
        let scorer = WeightedAdditiveScorer::new();
        // Stack enough signals to exceed 20
        let signals = vec![
            Signal::PostInstallAdded {
                previous_versions_without: 1,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 2,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 3,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 4,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 5,
            },
        ];
        let config = default_config();
        let score = scorer.score(&signals, &config);
        // 5 * 5.0 = 25.0 → capped at 20
        assert_eq!(score.value(), 20);
    }

    #[test]
    fn unknown_signal_label_gets_zero_weight() {
        let scorer = WeightedAdditiveScorer::new();
        // BinaryBlobInSource has weight 3.0, but let's verify with a signal
        // that might not be in config
        let signals = vec![Signal::BinaryBlobInSource {
            file: PathBuf::from("suspicious.dat"),
            entropy: 7.9,
            size_bytes: 1024,
        }];
        let mut config = default_config();
        // Remove the weight entry to simulate unknown signal
        config.weights.remove("binary-blob");
        let score = scorer.score(&signals, &config);
        assert_eq!(score.value(), 0);
    }

    #[test]
    fn custom_weights_respected() {
        let scorer = WeightedAdditiveScorer::new();
        let signals = vec![Signal::NewMaintainer {
            account_age_days: 1,
        }];
        let mut config = default_config();
        config.weights.insert("new-maintainer".into(), 10.0);
        let score = scorer.score(&signals, &config);
        assert_eq!(score.value(), 10);
    }
}
