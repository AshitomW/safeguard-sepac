//! The `Logger` trait — appends audit events to a signed log.
//!
//! Each [`AuditEvent`] is a serialisable, replayable log entry.

use crate::types::{AuditEvent, Result};

/// Appends audit events to a signed, append-only log.
///
/// # Responsibilities
/// - Serialising audit events to JSON
/// - Signing each entry with a keyed HMAC
/// - Appending to the log file atomically
///
/// # Design
/// The logger is append-only — it never modifies or deletes entries.
/// Each entry is one JSON object per line (JSONL), signed with HMAC.
/// The format is parseable by standard SIEM tooling without a custom parser.
pub trait Logger: Send + Sync {
    /// Logs an audit event.
    ///
    /// The implementation must sign the event and append it atomically
    /// to the audit log.
    fn log(&self, event: &AuditEvent) -> Result<()>;
}
