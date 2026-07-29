//! Audit logging, alerting, and reporting.
//!
//! Provides the signed, append-only audit log, terminal/JSON/HTML reporting,
//! and Slack/Webhook alert dispatching.

pub mod alerting;
pub mod logger;
pub mod report;

pub use alerting::{AlertDispatcher, AlertPayload};
