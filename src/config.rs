//! Configuration loading and validation for Safeguard.
//!
//! All thresholds, weights, syscall allowlists, and trust mode parameters
//! are data loaded from TOML — never hardcoded in application code.
//! The [`SandboxConfig`] uses a builder for safe construction.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, SafeguardError};
use crate::types::TrustMode;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Top-level Safeguard configuration, loaded from a TOML file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafeguardConfig {
    /// Active trust mode.
    #[serde(default)]
    pub trust_mode: TrustMode,

    /// Risk scoring parameters.
    #[serde(default)]
    pub scoring: ScoringConfig,

    /// Per-mode threshold and behaviour overrides.
    #[serde(default)]
    pub trust_modes: TrustModesConfig,

    /// Sandbox configuration.
    #[serde(default)]
    pub sandbox: SandboxConfig,

    /// Audit log configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

impl SafeguardConfig {
    /// Loads config from a TOML file at the given path.
    pub fn from_file(path: &Path) -> Result<Self, SafeguardError> {
        let content = std::fs::read_to_string(path).map_err(|_| {
            SafeguardError::Config(ConfigError::FileNotFound {
                path: path.to_path_buf(),
            })
        })?;
        Self::from_str(&content, path)
    }

    /// Parses config from a TOML string. `source_path` is used in error messages.
    pub fn from_str(content: &str, source_path: &Path) -> Result<Self, SafeguardError> {
        let config: Self = toml::from_str(content).map_err(|e| {
            SafeguardError::Config(ConfigError::ParseError {
                path: source_path.to_path_buf(),
                message: e.to_string(),
            })
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validates all config fields for internal consistency.
    fn validate(&self) -> Result<(), SafeguardError> {
        self.scoring.validate()?;
        self.trust_modes.validate()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scoring config
// ---------------------------------------------------------------------------

/// Configuration for the weighted additive risk scoring model.
///
/// Weights and thresholds are data, not code. The `Scorer` reads these
/// values — it never contains hardcoded numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Per-signal-label weight. Key = signal label (kebab-case), value = weight.
    #[serde(default = "ScoringConfig::default_weights")]
    pub weights: HashMap<String, f64>,

    /// Decision thresholds: `[allow_max, warn_max, block_max]`.
    /// Score > block_max → Critical.
    #[serde(default = "ScoringConfig::default_thresholds")]
    pub thresholds: DecisionThresholds,

    /// Maximum total score (scores are capped here).
    #[serde(default = "ScoringConfig::default_max_score")]
    pub max_score: u8,
}

impl ScoringConfig {
    /// Validates scoring config values.
    fn validate(&self) -> Result<(), SafeguardError> {
        if self.max_score == 0 {
            return Err(SafeguardError::Config(ConfigError::InvalidValue {
                field: "scoring.max_score".into(),
                message: "must be greater than 0".into(),
            }));
        }
        for (label, weight) in &self.weights {
            if *weight < 0.0 {
                return Err(SafeguardError::Config(ConfigError::InvalidValue {
                    field: format!("scoring.weights.{label}"),
                    message: "weight must be non-negative".into(),
                }));
            }
        }
        self.thresholds.validate()
    }

    fn default_weights() -> HashMap<String, f64> {
        let mut w = HashMap::new();
        w.insert("runtime-syscall".into(), 4.0);
        w.insert("post-install-added".into(), 5.0);
        w.insert("new-maintainer".into(), 3.0);
        w.insert("velocity-outlier".into(), 2.0);
        w.insert("binary-blob".into(), 3.0);
        w.insert("obfuscated-code".into(), 4.0);
        w.insert("dependency-added".into(), 1.0);
        w.insert("provenance-missing".into(), 2.0);
        w
    }

    fn default_max_score() -> u8 {
        20
    }

    fn default_thresholds() -> DecisionThresholds {
        DecisionThresholds::default()
    }
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weights: Self::default_weights(),
            thresholds: DecisionThresholds::default(),
            max_score: Self::default_max_score(),
        }
    }
}

// ---------------------------------------------------------------------------
// Decision thresholds
// ---------------------------------------------------------------------------

/// Score-range boundaries that map scores to decision tiers.
///
/// `allow_max` < `warn_max` < `block_max` ≤ max_score.
/// Scores above `block_max` are Critical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionThresholds {
    /// Maximum score for Allow (inclusive). Default: 4.
    pub allow_max: u8,
    /// Maximum score for Warn (inclusive). Default: 9.
    pub warn_max: u8,
    /// Maximum score for Block (inclusive). Default: 14.
    pub block_max: u8,
}

impl DecisionThresholds {
    /// Validates that thresholds are monotonically increasing.
    fn validate(&self) -> Result<(), SafeguardError> {
        if self.allow_max >= self.warn_max {
            return Err(SafeguardError::Config(ConfigError::InvalidValue {
                field: "scoring.thresholds".into(),
                message: format!(
                    "allow_max ({}) must be less than warn_max ({})",
                    self.allow_max, self.warn_max
                ),
            }));
        }
        if self.warn_max >= self.block_max {
            return Err(SafeguardError::Config(ConfigError::InvalidValue {
                field: "scoring.thresholds".into(),
                message: format!(
                    "warn_max ({}) must be less than block_max ({})",
                    self.warn_max, self.block_max
                ),
            }));
        }
        Ok(())
    }
}

impl Default for DecisionThresholds {
    fn default() -> Self {
        Self {
            allow_max: 4,
            warn_max: 9,
            block_max: 14,
        }
    }
}

// ---------------------------------------------------------------------------
// Trust mode config
// ---------------------------------------------------------------------------

/// Per-mode overrides for decision behaviour.
///
/// Adding a new trust mode is adding a config entry, not an `if/else` chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustModesConfig {
    /// Configuration for Paranoid mode.
    #[serde(default = "TrustModesConfig::default_paranoid")]
    pub paranoid: TrustModeConfig,

    /// Configuration for Balanced mode.
    #[serde(default = "TrustModesConfig::default_balanced")]
    pub balanced: TrustModeConfig,

    /// Configuration for YOLO mode.
    #[serde(default = "TrustModesConfig::default_yolo")]
    pub yolo: TrustModeConfig,
}

impl TrustModesConfig {
    /// Validates all mode configs.
    fn validate(&self) -> Result<(), SafeguardError> {
        self.paranoid.validate("paranoid")?;
        self.balanced.validate("balanced")?;
        self.yolo.validate("yolo")?;
        Ok(())
    }

    /// Returns the config for the given trust mode.
    pub fn for_mode(&self, mode: TrustMode) -> &TrustModeConfig {
        match mode {
            TrustMode::Paranoid => &self.paranoid,
            TrustMode::Balanced => &self.balanced,
            TrustMode::Yolo => &self.yolo,
        }
    }

    fn default_paranoid() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: false,
            warn_threshold_override: Some(0),
            block_threshold_override: Some(1),
        }
    }

    fn default_balanced() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: true,
            warn_threshold_override: None,
            block_threshold_override: None,
        }
    }

    fn default_yolo() -> TrustModeConfig {
        TrustModeConfig {
            force_allowed: true,
            warn_threshold_override: Some(14),
            block_threshold_override: Some(14),
        }
    }
}

impl Default for TrustModesConfig {
    fn default() -> Self {
        Self {
            paranoid: Self::default_paranoid(),
            balanced: Self::default_balanced(),
            yolo: Self::default_yolo(),
        }
    }
}

/// Configuration for a single trust mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustModeConfig {
    /// Whether `--force` can override a Block decision in this mode.
    /// Critical blocks are always enforced regardless of this setting.
    pub force_allowed: bool,

    /// If set, overrides the warn threshold for this mode.
    pub warn_threshold_override: Option<u8>,

    /// If set, overrides the block threshold for this mode.
    pub block_threshold_override: Option<u8>,
}

impl TrustModeConfig {
    /// Validates this mode config.
    fn validate(&self, mode_name: &str) -> Result<(), SafeguardError> {
        if let (Some(warn), Some(block)) =
            (self.warn_threshold_override, self.block_threshold_override)
            && warn > block
        {
            return Err(SafeguardError::Config(ConfigError::InvalidValue {
                field: format!("trust_modes.{mode_name}"),
                message: format!(
                    "warn_threshold_override ({warn}) must be less than or equal to block_threshold_override ({block})"
                ),
            }));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sandbox configuration
// ---------------------------------------------------------------------------

/// Configuration for the hardened sandbox.
///
/// Use [`SandboxConfigBuilder`] to construct instances safely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable network namespace (zero interfaces).
    #[serde(default = "default_true")]
    pub network_namespace: bool,

    /// Enable mount namespace (package dir ro + tmpfs).
    #[serde(default = "default_true")]
    pub mount_namespace: bool,

    /// Enable user namespace (UID mapping).
    #[serde(default = "default_true")]
    pub user_namespace: bool,

    /// Enable seccomp-bpf filtering.
    #[serde(default = "default_true")]
    pub seccomp_enabled: bool,

    /// Path to the syscall allowlist TOML file.
    #[serde(default = "SandboxConfig::default_allowlist_path")]
    pub syscall_allowlist_path: PathBuf,

    /// Maximum execution time in seconds before the sandbox is killed.
    #[serde(default = "SandboxConfig::default_timeout")]
    pub timeout_secs: u64,

    /// Maximum memory usage in bytes (cgroup limit).
    #[serde(default = "SandboxConfig::default_memory_limit")]
    pub memory_limit_bytes: u64,
}

impl SandboxConfig {
    /// Returns a builder for constructing a `SandboxConfig`.
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::default()
    }

    /// Returns `true` if all four isolation layers are enabled.
    pub fn is_fully_isolated(&self) -> bool {
        self.network_namespace
            && self.mount_namespace
            && self.user_namespace
            && self.seccomp_enabled
    }

    fn default_allowlist_path() -> PathBuf {
        PathBuf::from("/etc/safeguard/syscall_allowlist.toml")
    }

    fn default_timeout() -> u64 {
        30
    }

    fn default_memory_limit() -> u64 {
        256 * 1024 * 1024 // 256 MiB
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            network_namespace: true,
            mount_namespace: true,
            user_namespace: true,
            seccomp_enabled: true,
            syscall_allowlist_path: Self::default_allowlist_path(),
            timeout_secs: Self::default_timeout(),
            memory_limit_bytes: Self::default_memory_limit(),
        }
    }
}

/// Builder for [`SandboxConfig`]. Ensures safe, incremental construction.
#[derive(Debug, Default)]
pub struct SandboxConfigBuilder {
    network_namespace: Option<bool>,
    mount_namespace: Option<bool>,
    user_namespace: Option<bool>,
    seccomp_enabled: Option<bool>,
    syscall_allowlist_path: Option<PathBuf>,
    timeout_secs: Option<u64>,
    memory_limit_bytes: Option<u64>,
}

impl SandboxConfigBuilder {
    /// Sets whether to enable the network namespace.
    pub fn network_namespace(mut self, enabled: bool) -> Self {
        self.network_namespace = Some(enabled);
        self
    }

    /// Sets whether to enable the mount namespace.
    pub fn mount_namespace(mut self, enabled: bool) -> Self {
        self.mount_namespace = Some(enabled);
        self
    }

    /// Sets whether to enable the user namespace.
    pub fn user_namespace(mut self, enabled: bool) -> Self {
        self.user_namespace = Some(enabled);
        self
    }

    /// Sets whether to enable seccomp-bpf filtering.
    pub fn seccomp_enabled(mut self, enabled: bool) -> Self {
        self.seccomp_enabled = Some(enabled);
        self
    }

    /// Sets the path to the syscall allowlist TOML file.
    pub fn syscall_allowlist_path(mut self, path: PathBuf) -> Self {
        self.syscall_allowlist_path = Some(path);
        self
    }

    /// Sets the execution timeout in seconds.
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    /// Sets the memory limit in bytes.
    pub fn memory_limit_bytes(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = Some(bytes);
        self
    }

    /// Builds the `SandboxConfig`, using defaults for unset fields.
    pub fn build(self) -> SandboxConfig {
        let defaults = SandboxConfig::default();
        SandboxConfig {
            network_namespace: self.network_namespace.unwrap_or(defaults.network_namespace),
            mount_namespace: self.mount_namespace.unwrap_or(defaults.mount_namespace),
            user_namespace: self.user_namespace.unwrap_or(defaults.user_namespace),
            seccomp_enabled: self.seccomp_enabled.unwrap_or(defaults.seccomp_enabled),
            syscall_allowlist_path: self
                .syscall_allowlist_path
                .unwrap_or(defaults.syscall_allowlist_path),
            timeout_secs: self.timeout_secs.unwrap_or(defaults.timeout_secs),
            memory_limit_bytes: self
                .memory_limit_bytes
                .unwrap_or(defaults.memory_limit_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit config
// ---------------------------------------------------------------------------

/// Configuration for the audit logging subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to the audit log file.
    #[serde(default = "AuditConfig::default_log_path")]
    pub log_path: PathBuf,

    /// Path to the HMAC key file for signing audit entries.
    #[serde(default = "AuditConfig::default_key_path")]
    pub hmac_key_path: PathBuf,
}

impl AuditConfig {
    fn default_log_path() -> PathBuf {
        PathBuf::from("/var/log/safeguard/audit.jsonl")
    }

    fn default_key_path() -> PathBuf {
        PathBuf::from("/etc/safeguard/hmac.key")
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: Self::default_log_path(),
            hmac_key_path: Self::default_key_path(),
        }
    }
}

// ---------------------------------------------------------------------------
// Syscall allowlist
// ---------------------------------------------------------------------------

/// A syscall allowlist loaded from TOML config.
///
/// The allowlist is data, not code. It is loaded at startup and passed
/// to the seccomp filter builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAllowlist {
    /// Allowed syscall names.
    pub allowed: Vec<String>,
}

impl SyscallAllowlist {
    /// Loads the allowlist from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, SafeguardError> {
        let content = std::fs::read_to_string(path).map_err(|_| {
            SafeguardError::Config(ConfigError::FileNotFound {
                path: path.to_path_buf(),
            })
        })?;
        let list: Self = toml::from_str(&content).map_err(|e| {
            SafeguardError::Config(ConfigError::ParseError {
                path: path.to_path_buf(),
                message: e.to_string(),
            })
        })?;
        Ok(list)
    }

    /// Returns `true` if the given syscall name is in the allowlist.
    pub fn is_allowed(&self, syscall_name: &str) -> bool {
        self.allowed.iter().any(|s| s == syscall_name)
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let config = SafeguardConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn sandbox_builder_defaults() {
        let config = SandboxConfig::builder().build();
        assert!(config.is_fully_isolated());
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn sandbox_builder_overrides() {
        let config = SandboxConfig::builder()
            .network_namespace(false)
            .timeout_secs(60)
            .build();
        assert!(!config.network_namespace);
        assert!(config.mount_namespace);
        assert_eq!(config.timeout_secs, 60);
        assert!(!config.is_fully_isolated());
    }

    #[test]
    fn invalid_thresholds_rejected() {
        let mut config = SafeguardConfig::default();
        config.scoring.thresholds.allow_max = 10;
        config.scoring.thresholds.warn_max = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn negative_weight_rejected() {
        let mut config = SafeguardConfig::default();
        config.scoring.weights.insert("test".into(), -1.0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn trust_mode_config_lookup() {
        let modes = TrustModesConfig::default();
        let paranoid = modes.for_mode(TrustMode::Paranoid);
        assert!(!paranoid.force_allowed);
        let balanced = modes.for_mode(TrustMode::Balanced);
        assert!(balanced.force_allowed);
    }

    #[test]
    fn parse_minimal_toml() {
        let toml = r#"
            trust_mode = "Balanced"
        "#;
        let config = SafeguardConfig::from_str(toml, Path::new("test.toml")).unwrap();
        assert_eq!(config.trust_mode, TrustMode::Balanced);
    }

    #[test]
    fn parse_full_toml() {
        let toml = r#"
            trust_mode = "Paranoid"

            [scoring]
            max_score = 20

            [scoring.thresholds]
            allow_max = 3
            warn_max = 7
            block_max = 12

            [scoring.weights]
            runtime-syscall = 5.0
            post-install-added = 6.0

            [sandbox]
            timeout_secs = 60
            network_namespace = true

            [audit]
            log_path = "/tmp/audit.jsonl"
        "#;
        let config = SafeguardConfig::from_str(toml, Path::new("test.toml")).unwrap();
        assert_eq!(config.trust_mode, TrustMode::Paranoid);
        assert_eq!(config.scoring.thresholds.allow_max, 3);
        assert_eq!(config.sandbox.timeout_secs, 60);
    }

    #[test]
    fn syscall_allowlist_check() {
        let list = SyscallAllowlist {
            allowed: vec!["read".into(), "write".into(), "exit".into()],
        };
        assert!(list.is_allowed("read"));
        assert!(!list.is_allowed("connect"));
    }
}
