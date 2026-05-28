//! File-based audit logger with HMAC signing.
//!
//! Each log entry is one JSON object per line (JSONL), signed with a
//! keyed HMAC-SHA256. The log is append-only — entries are never modified
//! or deleted. The format is parseable by standard SIEM tooling without
//! a custom parser.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{AuditError, SafeguardError};
use crate::traits::Logger;
use crate::types::{AuditEvent, Result};

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// A signed audit entry — the JSON payload plus its HMAC signature.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedAuditEntry {
    /// The audit event payload.
    pub event: AuditEvent,
    /// Hex-encoded HMAC-SHA256 signature of the serialised event.
    pub hmac_signature: String,
}

/// Append-only file audit logger with HMAC signing.
///
/// # Design
/// - Each `AuditEvent` is a serialisable, replayable entry.
/// - **Append-only**: Never modifies or deletes existing entries.
/// - **HMAC-signed**: Each entry is signed for integrity verification.
/// - **SIEM-ready**: One JSON object per line, stable versioned schema.
pub struct FileAuditLogger {
    log_path: PathBuf,
    hmac_key: Vec<u8>,
}

impl FileAuditLogger {
    /// Creates a new audit logger.
    ///
    /// The log file is created if it doesn't exist. The HMAC key is
    /// used to sign each entry.
    pub fn new(log_path: PathBuf, hmac_key: Vec<u8>) -> Self {
        Self { log_path, hmac_key }
    }

    /// Creates a logger from config paths, reading the HMAC key from file.
    pub fn from_paths(log_path: &Path, hmac_key_path: &Path) -> Result<Self> {
        let hmac_key = std::fs::read(hmac_key_path).map_err(|e| {
            SafeguardError::Audit(AuditError::HmacError {
                message: format!(
                    "failed to read HMAC key from {}: {e}",
                    hmac_key_path.display()
                ),
            })
        })?;
        Ok(Self::new(log_path.to_path_buf(), hmac_key))
    }

    /// Computes the HMAC-SHA256 signature for a JSON payload.
    fn sign(&self, json_bytes: &[u8]) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).map_err(|e| {
            SafeguardError::Audit(AuditError::HmacError {
                message: format!("invalid HMAC key: {e}"),
            })
        })?;
        mac.update(json_bytes);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}

impl Logger for FileAuditLogger {
    fn log(&self, event: &AuditEvent) -> Result<()> {
        let event_json = serde_json::to_string(event).map_err(|e| {
            SafeguardError::Audit(AuditError::WriteFailed {
                path: self.log_path.clone(),
                message: format!("JSON serialisation failed: {e}"),
            })
        })?;

        let signature = self.sign(event_json.as_bytes())?;

        let entry = SignedAuditEntry {
            event: event.clone(),
            hmac_signature: signature,
        };

        let mut line = serde_json::to_string(&entry).map_err(|e| {
            SafeguardError::Audit(AuditError::WriteFailed {
                path: self.log_path.clone(),
                message: format!("JSON serialisation failed: {e}"),
            })
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| {
                SafeguardError::Audit(AuditError::WriteFailed {
                    path: self.log_path.clone(),
                    message: format!("failed to open log file: {e}"),
                })
            })?;

        file.write_all(line.as_bytes()).map_err(|e| {
            SafeguardError::Audit(AuditError::WriteFailed {
                path: self.log_path.clone(),
                message: format!("write failed: {e}"),
            })
        })?;

        Ok(())
    }
}

/// Hex encoding helper (avoids adding the `hex` crate for this one use).
mod hex {
    /// Encodes bytes as a lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::{Decision, Ecosystem, PackageId, RiskScore, TrustMode};

    fn test_event() -> AuditEvent {
        AuditEvent {
            schema_version: AuditEvent::CURRENT_SCHEMA_VERSION,
            timestamp: Utc::now(),
            package_id: PackageId {
                name: "test-pkg".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            risk_score: RiskScore::new(7),
            decision: Decision::Warn {
                reasons: vec!["test warning".into()],
            },
            signals: vec![],
            trust_mode: TrustMode::Balanced,
            force_override: false,
            force_reason: None,
        }
    }

    #[test]
    fn log_creates_file_and_writes_entry() {
        let dir = std::env::temp_dir().join("safeguard_test_audit");
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("test_audit.jsonl");

        // Clean up from previous runs
        let _ = std::fs::remove_file(&log_path);

        let logger = FileAuditLogger::new(log_path.clone(), b"test-secret-key".to_vec());
        logger.log(&test_event()).unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        // Verify it's valid JSON
        let entry: SignedAuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry.event.package_id.name, "test-pkg");
        assert!(!entry.hmac_signature.is_empty());

        // Clean up
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn log_appends_multiple_entries() {
        let dir = std::env::temp_dir().join("safeguard_test_audit");
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("test_audit_multi.jsonl");
        let _ = std::fs::remove_file(&log_path);

        let logger = FileAuditLogger::new(log_path.clone(), b"test-key".to_vec());
        logger.log(&test_event()).unwrap();
        logger.log(&test_event()).unwrap();
        logger.log(&test_event()).unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        // Clean up
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn hmac_signature_is_deterministic() {
        let logger = FileAuditLogger::new(PathBuf::new(), b"key".to_vec());
        let sig1 = logger.sign(b"test data").unwrap();
        let sig2 = logger.sign(b"test data").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn hmac_signature_varies_with_data() {
        let logger = FileAuditLogger::new(PathBuf::new(), b"key".to_vec());
        let sig1 = logger.sign(b"data A").unwrap();
        let sig2 = logger.sign(b"data B").unwrap();
        assert_ne!(sig1, sig2);
    }
}
