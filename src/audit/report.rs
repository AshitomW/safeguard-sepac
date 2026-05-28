//! Terminal and JSON reporting for install decisions.
//!
//! The terminal report shows structured output for blocked installs.
//! The JSON report (`--json`) emits a stable, versioned schema.

use crate::types::{AuditEvent, Decision, Signal};

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable terminal output.
    Terminal,
    /// Machine-readable JSON (stable schema).
    Json,
}

/// Formats an audit event for display.
///
/// # Terminal format
/// Shows package, version, score, decision, each signal with detail,
/// historical baseline summary, and available options (diff, report, force).
///
/// # JSON format
/// Emits the `AuditEvent` as a versioned JSON object. The schema version
/// is a field in every output — never break the schema.
pub fn format_report(event: &AuditEvent, format: OutputFormat) -> String {
    match format {
        OutputFormat::Terminal => format_terminal(event),
        OutputFormat::Json => format_json(event),
    }
}

/// Formats the terminal report.
fn format_terminal(event: &AuditEvent) -> String {
    let mut out = String::new();

    // Header
    out.push_str("\n╔══════════════════════════════════════════════════════╗\n");
    out.push_str("║  SAFEGUARD — Package Risk Report                    ║\n");
    out.push_str("╚══════════════════════════════════════════════════════╝\n\n");

    // Package info
    out.push_str(&format!(
        "  Package:    {}@{} ({})\n",
        event.package_id.name, event.package_id.version, event.package_id.ecosystem
    ));
    out.push_str(&format!("  Score:      {}\n", event.risk_score));
    out.push_str(&format!(
        "  Decision:   {}\n",
        decision_label(&event.decision)
    ));
    out.push_str(&format!("  Trust Mode: {}\n", event.trust_mode));

    // Signals
    if event.signals.is_empty() {
        out.push_str("\n  No risk signals detected.\n");
    } else {
        out.push_str(&format!("\n  Signals ({}):\n", event.signals.len()));
        for signal in &event.signals {
            out.push_str(&format_signal(signal));
        }
    }

    // Decision details
    match &event.decision {
        Decision::Block { reasons } | Decision::Critical { reasons } => {
            out.push_str("\n  ── Blocked ──\n");
            for reason in reasons {
                out.push_str(&format!("    • {reason}\n"));
            }
            out.push_str("\n  Options:\n");
            out.push_str("    --diff     Show detailed diff with previous version\n");
            out.push_str("    --report   Save full report to file\n");
            if matches!(event.decision, Decision::Block { .. }) {
                out.push_str("    --force \"reason\"  Override block (logged to audit trail)\n");
            }
        }
        Decision::Warn { reasons } => {
            out.push_str("\n  ── Warning ──\n");
            for reason in reasons {
                out.push_str(&format!("    • {reason}\n"));
            }
        }
        Decision::Allow => {}
    }

    out.push('\n');
    out
}

/// Formats a single signal for terminal display.
fn format_signal(signal: &Signal) -> String {
    format!(
        "    [{label}] {detail}\n",
        label = signal.label(),
        detail = signal.detail()
    )
}

/// Returns a human-readable label for a decision.
fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "ALLOW",
        Decision::Warn { .. } => "WARN",
        Decision::Block { .. } => "BLOCK",
        Decision::Critical { .. } => "CRITICAL",
    }
}

/// Formats the JSON report with stable versioned schema.
fn format_json(event: &AuditEvent) -> String {
    // serde_json::to_string_pretty for readable output.
    // Schema version is embedded in AuditEvent.
    serde_json::to_string_pretty(event)
        .unwrap_or_else(|e| format!("{{\"error\": \"JSON serialisation failed: {e}\"}}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::{Ecosystem, PackageId, RiskScore, TrustMode};

    fn test_event(decision: Decision, signals: Vec<Signal>) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            timestamp: Utc::now(),
            package_id: PackageId {
                name: "evil-pkg".into(),
                version: "6.6.6".into(),
                ecosystem: Ecosystem::Npm,
            },
            risk_score: RiskScore::new(12),
            decision,
            signals,
            trust_mode: TrustMode::Balanced,
            force_override: false,
            force_reason: None,
        }
    }

    #[test]
    fn terminal_report_contains_package_info() {
        let event = test_event(Decision::Allow, vec![]);
        let report = format_report(&event, OutputFormat::Terminal);
        assert!(report.contains("evil-pkg@6.6.6"));
        assert!(report.contains("npm"));
        assert!(report.contains("ALLOW"));
    }

    #[test]
    fn terminal_report_shows_signals() {
        let signals = vec![Signal::NewMaintainer {
            account_age_days: 2,
        }];
        let event = test_event(
            Decision::Warn {
                reasons: vec!["suspicious".into()],
            },
            signals,
        );
        let report = format_report(&event, OutputFormat::Terminal);
        assert!(report.contains("[new-maintainer]"));
        assert!(report.contains("account age 2 days"));
    }

    #[test]
    fn terminal_report_shows_block_options() {
        let event = test_event(
            Decision::Block {
                reasons: vec!["high risk".into()],
            },
            vec![],
        );
        let report = format_report(&event, OutputFormat::Terminal);
        assert!(report.contains("--diff"));
        assert!(report.contains("--force"));
        assert!(report.contains("BLOCK"));
    }

    #[test]
    fn json_report_is_valid_json() {
        let event = test_event(Decision::Allow, vec![]);
        let json = format_report(&event, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["package_id"]["name"], "evil-pkg");
    }

    #[test]
    fn json_report_contains_schema_version() {
        let event = test_event(Decision::Allow, vec![]);
        let json = format_report(&event, OutputFormat::Json);
        assert!(json.contains("\"schema_version\""));
    }
}
