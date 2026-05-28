//! The `Scorer` trait — computes a risk score from signals.
//!
//! The default scoring is a weighted additive model, but alternative
//! scoring algorithms can be swapped in.

use crate::config::ScoringConfig;
use crate::types::{RiskScore, Signal};

/// Computes a [`RiskScore`] from a set of risk signals.
///
/// # Responsibilities
/// - Mapping signal types to weights
/// - Aggregating weighted values into a bounded score
///
/// # Design
/// Swappable scoring — the scorer is a pure function of (signals, config).
/// It never reads from the filesystem or network. CPU-bound, synchronous.
///
/// # Invariant
/// The returned score is always in `[0, config.max_score]`.
pub trait Scorer: Send + Sync {
    /// Computes a risk score from the given signals using the provided config.
    ///
    /// The implementation must cap the result at `config.max_score`.
    fn score(&self, signals: &[Signal], config: &ScoringConfig) -> RiskScore;
}
