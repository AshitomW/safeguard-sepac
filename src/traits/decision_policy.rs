//! The `DecisionPolicy` trait — maps risk scores to decisions.
//!
//! The policy is trust-mode-aware and can be swapped:
//! the same score may produce different decisions under Paranoid vs YOLO.

use crate::config::TrustModeConfig;
use crate::types::{Decision, RiskScore, TrustMode};

/// Makes allow/warn/block/critical decisions based on a risk score and trust mode.
///
/// # Responsibilities
/// - Mapping a `RiskScore` to a `Decision` variant
/// - Applying trust-mode-specific threshold overrides
///
/// # Design
/// The policy reads thresholds from `TrustModeConfig` (is swappable).
/// Adding a new trust mode is adding a config entry, not an `if/else` chain.
/// The policy never accesses the filesystem, network, or any other state.
pub trait DecisionPolicy: Send + Sync {
    /// Decides whether to allow, warn, block, or critically block an install.
    ///
    /// The `mode` and `config` together determine the thresholds applied
    /// to the `score`.
    fn decide(&self, score: RiskScore, mode: TrustMode, config: &TrustModeConfig) -> Decision;
}
