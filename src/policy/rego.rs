//! Policy-as-Code engine for enterprise rules.

use serde::{Deserialize, Serialize};

use crate::types::{Decision, Ecosystem, RiskScore, Signal};

/// Custom enterprise policy rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule identifier (e.g. "block-pypi-high-risk").
    pub id: String,
    /// Human-readable rule description.
    pub description: String,
    /// Ecosystem constraint.
    pub target_ecosystem: Option<Ecosystem>,
    /// Minimum score threshold that triggers this rule.
    pub min_score: Option<u8>,
    /// Specific signal label required to trigger rule.
    pub required_signal_label: Option<String>,
}

/// Evaluator for custom policy-as-code rules.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    pub rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Creates a new `PolicyEngine`.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a rule to the engine.
    pub fn add_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Evaluates custom policy rules against a package analysis result.
    ///
    /// Returns `Some(Decision::Block)` if any custom enterprise rule is violated.
    pub fn evaluate(
        &self,
        ecosystem: Ecosystem,
        score: RiskScore,
        signals: &[Signal],
    ) -> Option<Decision> {
        let mut violations = Vec::new();

        for rule in &self.rules {
            if let Some(eco) = rule.target_ecosystem {
                if eco != ecosystem {
                    continue;
                }
            }

            if let Some(min_s) = rule.min_score {
                if score.value() < min_s {
                    continue;
                }
            }

            if let Some(label) = &rule.required_signal_label {
                let has_signal = signals.iter().any(|s| s.label() == label);
                if !has_signal {
                    continue;
                }
            }

            violations.push(format!("Policy Rule Violated [{}] {}", rule.id, rule.description));
        }

        if violations.is_empty() {
            None
        } else {
            Some(Decision::Block { reasons: violations })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rule_evaluation() {
        let engine = PolicyEngine::new().add_rule(PolicyRule {
            id: "no-secret-exfil".into(),
            description: "Secrets must never be present in published code".into(),
            target_ecosystem: None,
            min_score: None,
            required_signal_label: Some("secret-exposed".into()),
        });

        let sig = Signal::SecretExposed {
            file: "config.js".into(),
            secret_type: "AWS".into(),
            line: 10,
        };

        let decision = engine.evaluate(Ecosystem::Npm, RiskScore::new(5), &[sig]);
        assert!(decision.is_some());
        assert!(decision.unwrap().is_blocked());
    }
}
