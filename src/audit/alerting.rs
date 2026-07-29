//! Alerting and notification system (Slack, Webhook).

use reqwest::Client;
use serde::Serialize;

use crate::types::{AuditEvent, Decision, Result};

/// Webhook alert payload.
#[derive(Debug, Serialize)]
pub struct AlertPayload {
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: String,
    pub risk_score: u8,
    pub decision: String,
    pub signal_count: usize,
}

/// Alert dispatcher for high-risk audit events.
#[derive(Debug)]
pub struct AlertDispatcher {
    client: Client,
    slack_webhook_url: Option<String>,
    generic_webhook_url: Option<String>,
}

impl Default for AlertDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertDispatcher {
    /// Creates a new `AlertDispatcher`.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            slack_webhook_url: None,
            generic_webhook_url: None,
        }
    }

    /// Configures Slack webhook URL.
    pub fn with_slack_webhook(mut self, url: String) -> Self {
        self.slack_webhook_url = Some(url);
        self
    }

    /// Configures generic HTTP webhook URL.
    pub fn with_generic_webhook(mut self, url: String) -> Self {
        self.generic_webhook_url = Some(url);
        self
    }

    /// Dispatches alerts if event decision is Block or Critical.
    pub async fn notify_if_blocked(&self, event: &AuditEvent) -> Result<()> {
        if !event.decision.is_blocked() {
            return Ok(());
        }

        let dec_str = match &event.decision {
            Decision::Block { .. } => "BLOCK",
            Decision::Critical { .. } => "CRITICAL",
            _ => "UNKNOWN",
        };

        let payload = AlertPayload {
            package_name: event.package_id.name.clone(),
            package_version: event.package_id.version.clone(),
            ecosystem: event.package_id.ecosystem.to_string(),
            risk_score: event.risk_score.value(),
            decision: dec_str.to_string(),
            signal_count: event.signals.len(),
        };

        // Dispatch Slack alert
        if let Some(url) = &self.slack_webhook_url {
            let text = format!(
                "🚨 *SAFEGUARD ALERT*: Blocked `{}`@`{}` ({}) with risk score {}/20 ({} signals)",
                payload.package_name,
                payload.package_version,
                payload.ecosystem,
                payload.risk_score,
                payload.signal_count
            );

            let body = serde_json::json!({ "text": text });
            let _ = self.client.post(url).json(&body).send().await;
        }

        // Dispatch generic webhook alert
        if let Some(url) = &self.generic_webhook_url {
            let _ = self.client.post(url).json(&payload).send().await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_dispatcher_builder() {
        let dispatcher = AlertDispatcher::new()
            .with_slack_webhook("https://hooks.slack.com/services/test".into());

        assert!(dispatcher.slack_webhook_url.is_some());
    }
}
