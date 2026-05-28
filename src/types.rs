//! Core domain types shared across all Safeguard layers.
//!
//! Every type here is a value object or data carrier with no business logic.
//! Types are designed to be serialisable, cloneable, and cheaply constructible.
//! No type in this module depends on any other Safeguard module except [`crate::error`].

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SafeguardError;

// ---------------------------------------------------------------------------
// Result alias
// ---------------------------------------------------------------------------

/// Convenience result type used throughout Safeguard.
pub type Result<T> = std::result::Result<T, SafeguardError>;

// ---------------------------------------------------------------------------
// Package identity
// ---------------------------------------------------------------------------

/// Uniquely identifies a package within an ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageId {
    /// Package name as registered in the ecosystem (e.g. `"lodash"`).
    pub name: String,
    /// Exact version string (e.g. `"4.17.21"`).
    pub version: String,
    /// Which ecosystem this package belongs to.
    pub ecosystem: Ecosystem,
}

/// Supported package ecosystems.
///
/// Each variant maps 1:1 to a `RegistryAdapter` implementation.
/// Adding a new ecosystem means adding a variant here and a new adapter —
/// no changes to any other layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    /// Node.js / npm registry.
    Npm,
    /// Python Package Index.
    PyPi,
    /// Rust / crates.io.
    Cargo,
    /// RubyGems.org.
    RubyGems,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPi => write!(f, "pypi"),
            Self::Cargo => write!(f, "cargo"),
            Self::RubyGems => write!(f, "rubygems"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trust mode
// ---------------------------------------------------------------------------

/// Controls how aggressively Safeguard enforces risk decisions.
///
/// This is config, not code. `DecisionPolicy` reads the active mode and
/// applies the corresponding thresholds — no `if/else` chains per mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustMode {
    /// Block on any non-zero signal. Highest security.
    Paranoid,
    /// Default mode. Block on high scores, warn on medium.
    #[default]
    Balanced,
    /// Warn on critical only. For development environments.
    Yolo,
}

impl std::fmt::Display for TrustMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paranoid => write!(f, "paranoid"),
            Self::Balanced => write!(f, "balanced"),
            Self::Yolo => write!(f, "yolo"),
        }
    }
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The final gate decision for a package install.
///
/// Variants are ordered by severity. The `DecisionPolicy` maps a `RiskScore`
/// range to one of these based on the active `TrustMode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Score 0–4: install proceeds, event logged silently.
    Allow,
    /// Score 5–9: install proceeds, report printed to terminal.
    Warn {
        /// Human-readable reasons for the warning.
        reasons: Vec<String>,
    },
    /// Score 10–14: install blocked unless `--force` with a reason string.
    Block {
        /// Human-readable reasons for the block.
        reasons: Vec<String>,
    },
    /// Score 15–20: blocked in all modes; `--force` writes a signed audit entry.
    Critical {
        /// Human-readable reasons for the critical block.
        reasons: Vec<String>,
    },
}

impl Decision {
    /// Returns `true` if the install should proceed without user intervention.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Warn { .. })
    }

    /// Returns `true` if the install is blocked (requires `--force` or denied).
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. } | Self::Critical { .. })
    }
}

// ---------------------------------------------------------------------------
// Risk score
// ---------------------------------------------------------------------------

/// A bounded risk score in the range `[0, 20]`.
///
/// Constructed via [`RiskScore::new`] which enforces the upper bound.
/// The inner value is accessible via [`RiskScore::value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RiskScore(u8);

impl RiskScore {
    /// Maximum possible risk score.
    pub const MAX: u8 = 20;

    /// Creates a new `RiskScore`, capping the value at [`Self::MAX`].
    pub fn new(value: u8) -> Self {
        Self(value.min(Self::MAX))
    }

    /// Returns the raw score value.
    pub fn value(self) -> u8 {
        self.0
    }

    /// Returns the `Decision` tier this score falls into (before trust-mode adjustment).
    pub fn tier(self) -> DecisionTier {
        match self.0 {
            0..=4 => DecisionTier::Allow,
            5..=9 => DecisionTier::Warn,
            10..=14 => DecisionTier::Block,
            15..=20 => DecisionTier::Critical,
            // SAFETY: Constructor caps at 20, so this is unreachable.
            _ => unreachable!("RiskScore is bounded to 0–20"),
        }
    }
}

impl std::fmt::Display for RiskScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/20", self.0)
    }
}

/// The decision tier derived from a raw score, before trust-mode adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionTier {
    /// 0–4
    Allow,
    /// 5–9
    Warn,
    /// 10–14
    Block,
    /// 15–20
    Critical,
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// A typed risk signal emitted by analysers or the sandbox runtime.
///
/// Each variant carries the evidence that produced it. Signals are never
/// strings — they are structured data that the `Scorer` can weight
/// deterministically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signal {
    /// A syscall was observed at runtime that has no historical precedent.
    RuntimeSyscall {
        /// Syscall name (e.g. `"connect"`, `"execve"`).
        name: String,
        /// Stringified argument summary.
        args: String,
        /// How many times this syscall appeared in previous version baselines.
        historical_occurrences: u64,
    },

    /// A post-install script was added in this version that no previous version had.
    PostInstallAdded {
        /// Number of previous versions that did *not* have a post-install script.
        previous_versions_without: u64,
    },

    /// The package has a new maintainer (ownership transfer risk).
    NewMaintainer {
        /// How old the new maintainer's account is, in days.
        account_age_days: u64,
    },

    /// This version was published unusually quickly after the previous one.
    VelocityOutlier {
        /// Seconds between this publish and the previous version.
        gap_seconds: u64,
        /// Median publish gap across the package's history.
        median_gap_seconds: u64,
    },

    /// A high-entropy binary blob was found in the source tree.
    BinaryBlobInSource {
        /// Path to the file within the package archive.
        file: PathBuf,
        /// Shannon entropy of the file (0.0–8.0 for bytes).
        entropy: f64,
        /// File size in bytes.
        size_bytes: usize,
    },

    /// Obfuscated code patterns detected (eval, hex encoding, base64 blocks).
    ObfuscatedCode {
        /// Path to the file within the package archive.
        file: PathBuf,
        /// Description of the obfuscation pattern found.
        pattern: String,
        /// Confidence score (0.0–1.0).
        confidence: f64,
    },

    /// A dependency was added that was not in the previous version.
    DependencyAdded {
        /// Name of the new dependency.
        dependency_name: String,
        /// Version constraint specified.
        version_constraint: String,
    },

    /// Provenance verification failed or is missing.
    ProvenanceMissing {
        /// What was expected (e.g. "Sigstore attestation").
        expected: String,
    },
}

impl Signal {
    /// Returns a human-readable label for this signal type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::RuntimeSyscall { .. } => "runtime-syscall",
            Self::PostInstallAdded { .. } => "post-install-added",
            Self::NewMaintainer { .. } => "new-maintainer",
            Self::VelocityOutlier { .. } => "velocity-outlier",
            Self::BinaryBlobInSource { .. } => "binary-blob",
            Self::ObfuscatedCode { .. } => "obfuscated-code",
            Self::DependencyAdded { .. } => "dependency-added",
            Self::ProvenanceMissing { .. } => "provenance-missing",
        }
    }

    /// Returns a human-readable detail string for terminal reporting.
    pub fn detail(&self) -> String {
        match self {
            Self::RuntimeSyscall {
                name,
                args,
                historical_occurrences,
            } => {
                format!("syscall {name}({args}) — {historical_occurrences} historical occurrences")
            }
            Self::PostInstallAdded {
                previous_versions_without,
            } => {
                format!(
                    "post-install script added — {previous_versions_without} previous versions without"
                )
            }
            Self::NewMaintainer { account_age_days } => {
                format!("new maintainer — account age {account_age_days} days")
            }
            Self::VelocityOutlier {
                gap_seconds,
                median_gap_seconds,
            } => {
                format!("published {gap_seconds}s after previous (median: {median_gap_seconds}s)")
            }
            Self::BinaryBlobInSource {
                file,
                entropy,
                size_bytes,
            } => {
                format!(
                    "binary blob in {} — entropy {entropy:.2}, {size_bytes} bytes",
                    file.display()
                )
            }
            Self::ObfuscatedCode {
                file,
                pattern,
                confidence,
            } => {
                format!(
                    "obfuscated code in {} — {pattern} (confidence: {confidence:.2})",
                    file.display()
                )
            }
            Self::DependencyAdded {
                dependency_name,
                version_constraint,
            } => {
                format!("new dependency: {dependency_name}@{version_constraint}")
            }
            Self::ProvenanceMissing { expected } => {
                format!("provenance missing — expected: {expected}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Syscall log
// ---------------------------------------------------------------------------

/// A single captured syscall event from the eBPF tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Syscall name (resolved from number).
    pub name: String,
    /// Stringified arguments.
    pub args: String,
    /// Return value.
    pub return_code: i64,
    /// Timestamp relative to sandbox start.
    pub elapsed_ms: u64,
}

/// The complete syscall trace captured during a sandbox execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallLog {
    /// Ordered list of captured syscall events.
    pub entries: Vec<SyscallEntry>,
    /// Total execution wall-clock time in milliseconds.
    pub duration_ms: u64,
    /// Whether the sandbox process was killed by seccomp.
    pub killed_by_seccomp: bool,
    /// The signal number if the process was killed.
    pub kill_signal: Option<i32>,
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/// Historical baseline for a package — aggregated syscall fingerprint and signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Package this baseline belongs to.
    pub package_id: PackageId,
    /// Set of syscall names observed across historical versions.
    pub known_syscalls: Vec<String>,
    /// Number of versions included in this baseline.
    pub version_count: u64,
    /// When this baseline was last updated.
    pub updated_at: DateTime<Utc>,
    /// Signal labels that have been seen before (for deduplication).
    pub known_signal_labels: Vec<String>,
}

// ---------------------------------------------------------------------------
// Package archive & metadata
// ---------------------------------------------------------------------------

/// A fetched package archive ready for analysis and sandbox execution.
#[derive(Debug, Clone)]
pub struct PackageArchive {
    /// Identity of the package.
    pub id: PackageId,
    /// Path to the extracted archive on the local filesystem.
    pub extracted_path: PathBuf,
    /// Parsed manifest metadata.
    pub manifest: PackageManifest,
    /// Raw tarball bytes (for checksum verification).
    pub tarball: Vec<u8>,
}

/// Parsed metadata from a package manifest (package.json, setup.py, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Direct dependencies: name → version constraint.
    pub dependencies: HashMap<String, String>,
    /// Install scripts (preinstall, postinstall, etc.).
    pub install_scripts: Vec<InstallScript>,
    /// Maintainer identifiers (usernames or emails).
    pub maintainers: Vec<String>,
    /// Whether the package contains native code (e.g. C extensions, WASM).
    pub has_native_code: bool,
}

/// A named install script from a package manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallScript {
    /// Script phase (e.g. `"preinstall"`, `"postinstall"`).
    pub phase: String,
    /// The command to execute.
    pub command: String,
}

/// Metadata about a single published version of a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMeta {
    /// Version string.
    pub version: String,
    /// When this version was published.
    pub published_at: Option<DateTime<Utc>>,
    /// Maintainer who published this version.
    pub published_by: Option<String>,
    /// Whether this version has been deprecated or yanked.
    pub yanked: bool,
}

/// A cryptographic checksum for integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    /// Hash algorithm (e.g. `"sha256"`, `"sha512"`).
    pub algorithm: String,
    /// Hex-encoded hash value.
    pub hex_digest: String,
}

/// Provenance attestation for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Whether a valid Sigstore attestation was found.
    pub sigstore_verified: bool,
    /// Build system that produced the package (e.g. `"GitHub Actions"`).
    pub build_system: Option<String>,
    /// Source repository URL.
    pub source_repo: Option<String>,
    /// Whether the build is reproducible.
    pub reproducible: Option<bool>,
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// A serialisable audit event for the audit log.
///
/// Each event is self-contained: it carries the full context needed to
/// reconstruct what happened, when, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version for forward compatibility. Never remove fields.
    pub schema_version: u32,
    /// When this event was created.
    pub timestamp: DateTime<Utc>,
    /// Package that was evaluated.
    pub package_id: PackageId,
    /// Computed risk score.
    pub risk_score: RiskScore,
    /// The decision that was made.
    pub decision: Decision,
    /// All signals that contributed to the score.
    pub signals: Vec<Signal>,
    /// Active trust mode when the decision was made.
    pub trust_mode: TrustMode,
    /// Whether `--force` was used to override a block.
    pub force_override: bool,
    /// Reason string provided with `--force`, if any.
    pub force_reason: Option<String>,
}

impl AuditEvent {
    /// Current schema version. Increment when adding fields, never remove.
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_score_caps_at_max() {
        let score = RiskScore::new(25);
        assert_eq!(score.value(), 20);
    }

    #[test]
    fn risk_score_preserves_valid_values() {
        for v in 0..=20 {
            assert_eq!(RiskScore::new(v).value(), v);
        }
    }

    #[test]
    fn risk_score_tier_boundaries() {
        assert_eq!(RiskScore::new(0).tier(), DecisionTier::Allow);
        assert_eq!(RiskScore::new(4).tier(), DecisionTier::Allow);
        assert_eq!(RiskScore::new(5).tier(), DecisionTier::Warn);
        assert_eq!(RiskScore::new(9).tier(), DecisionTier::Warn);
        assert_eq!(RiskScore::new(10).tier(), DecisionTier::Block);
        assert_eq!(RiskScore::new(14).tier(), DecisionTier::Block);
        assert_eq!(RiskScore::new(15).tier(), DecisionTier::Critical);
        assert_eq!(RiskScore::new(20).tier(), DecisionTier::Critical);
    }

    #[test]
    fn decision_is_allowed() {
        assert!(Decision::Allow.is_allowed());
        assert!(Decision::Warn { reasons: vec![] }.is_allowed());
        assert!(!Decision::Block { reasons: vec![] }.is_allowed());
        assert!(!Decision::Critical { reasons: vec![] }.is_allowed());
    }

    #[test]
    fn decision_is_blocked() {
        assert!(!Decision::Allow.is_blocked());
        assert!(!Decision::Warn { reasons: vec![] }.is_blocked());
        assert!(Decision::Block { reasons: vec![] }.is_blocked());
        assert!(Decision::Critical { reasons: vec![] }.is_blocked());
    }

    #[test]
    fn risk_score_display() {
        assert_eq!(RiskScore::new(7).to_string(), "7/20");
        assert_eq!(RiskScore::new(20).to_string(), "20/20");
    }

    #[test]
    fn ecosystem_display() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::PyPi.to_string(), "pypi");
        assert_eq!(Ecosystem::Cargo.to_string(), "cargo");
        assert_eq!(Ecosystem::RubyGems.to_string(), "rubygems");
    }

    #[test]
    fn signal_labels_are_kebab_case() {
        let signals = vec![
            Signal::RuntimeSyscall {
                name: "connect".into(),
                args: "".into(),
                historical_occurrences: 0,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 0,
            },
            Signal::NewMaintainer {
                account_age_days: 0,
            },
            Signal::VelocityOutlier {
                gap_seconds: 0,
                median_gap_seconds: 0,
            },
            Signal::BinaryBlobInSource {
                file: PathBuf::new(),
                entropy: 0.0,
                size_bytes: 0,
            },
            Signal::ObfuscatedCode {
                file: PathBuf::new(),
                pattern: String::new(),
                confidence: 0.0,
            },
            Signal::DependencyAdded {
                dependency_name: String::new(),
                version_constraint: String::new(),
            },
            Signal::ProvenanceMissing {
                expected: String::new(),
            },
        ];
        for signal in &signals {
            let label = signal.label();
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "label `{label}` is not kebab-case"
            );
        }
    }
}
