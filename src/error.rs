//! Layered error types for Safeguard.
//!
//! Every error is a typed enum with structured context — never a string.
//! The top-level [`SafeguardError`] composes layer-specific errors via
//! `#[from]` conversions so call sites can use `?` ergonomically.

use std::path::PathBuf;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Top-level error
// ---------------------------------------------------------------------------

/// Top-level error type composing all layer-specific errors.
///
/// All public-facing functions return `Result<T, SafeguardError>`.
#[derive(Debug, Error)]
pub enum SafeguardError {
    /// An error from the registry adapter layer.
    #[error("registry error: {0}")]
    Registry(#[from] RegistryError),

    /// An error from the static analysis layer.
    #[error("analysis error: {0}")]
    Analysis(#[from] AnalysisError),

    /// An error from the sandbox execution layer.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    /// An error from the policy engine layer.
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),

    /// An error from the audit logging layer.
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),

    /// A configuration error.
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    /// An I/O error not specific to any layer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Registry errors
// ---------------------------------------------------------------------------

/// Errors from fetching packages and metadata from registries.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The package was not found in the registry.
    #[error("package not found: {name}@{version} in {ecosystem}")]
    NotFound {
        /// Package name.
        name: String,
        /// Requested version.
        version: String,
        /// Ecosystem queried.
        ecosystem: String,
    },

    /// The fetched tarball did not match the expected checksum.
    #[error("checksum mismatch for {name}@{version}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Package name.
        name: String,
        /// Package version.
        version: String,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },

    /// The registry returned an HTTP error.
    #[error("HTTP {status_code} from {url}: {body}")]
    HttpError {
        /// HTTP status code.
        status_code: u16,
        /// Request URL.
        url: String,
        /// Response body excerpt.
        body: String,
    },

    /// Rate-limited by the registry.
    #[error("rate limited by {registry}, retry after {retry_after_secs}s")]
    RateLimited {
        /// Registry name.
        registry: String,
        /// Seconds until the rate limit resets.
        retry_after_secs: u64,
    },

    /// A network-level error (DNS, timeout, connection refused).
    #[error("network error fetching {url}: {message}")]
    Network {
        /// Request URL.
        url: String,
        /// Error description.
        message: String,
    },

    /// Failed to parse a response from the registry.
    #[error("parse error from {url}: {message}")]
    ParseError {
        /// Request URL.
        url: String,
        /// Description of the parse failure.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Analysis errors
// ---------------------------------------------------------------------------

/// Errors from static analysis of package contents.
#[derive(Debug, Error)]
pub enum AnalysisError {
    /// Failed to parse a source file for AST diffing.
    #[error("parse error in {file}: {message}")]
    ParseError {
        /// File that failed to parse.
        file: PathBuf,
        /// Parser error message.
        message: String,
    },

    /// The package format is not supported by the analyser.
    #[error("unsupported format: {format} in {file}")]
    UnsupportedFormat {
        /// The format encountered.
        format: String,
        /// File path.
        file: PathBuf,
    },

    /// The package archive is corrupted or cannot be extracted.
    #[error("archive extraction failed for {path}: {message}")]
    ExtractionFailed {
        /// Archive path.
        path: PathBuf,
        /// Error description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Sandbox errors
// ---------------------------------------------------------------------------

/// Errors from sandbox setup and execution.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Failed to create a Linux namespace.
    #[error("namespace setup failed ({namespace_type}): {message}")]
    NamespaceSetupFailed {
        /// Which namespace failed (e.g. `"network"`, `"mount"`, `"user"`).
        namespace_type: String,
        /// OS-level error message.
        message: String,
    },

    /// Failed to install the seccomp-bpf filter.
    #[error("seccomp filter installation failed: {message}")]
    SeccompFailed {
        /// Error description.
        message: String,
    },

    /// The sandboxed process violated the seccomp policy.
    #[error("seccomp violation: syscall {syscall_name} (nr {syscall_nr}) killed process")]
    SeccompViolation {
        /// Name of the blocked syscall.
        syscall_name: String,
        /// Syscall number.
        syscall_nr: u32,
    },

    /// eBPF program failed to attach or collect data.
    #[error("eBPF error: {message}")]
    EbpfError {
        /// Error description.
        message: String,
    },

    /// The sandbox execution timed out.
    #[error("sandbox execution timed out after {timeout_secs}s")]
    Timeout {
        /// Configured timeout in seconds.
        timeout_secs: u64,
    },

    /// Partial isolation detected — this is a fatal error per AGENT.md.
    #[error("partial isolation: {missing_layers:?} layers failed to initialise — aborting")]
    PartialIsolation {
        /// Names of the layers that failed to initialise.
        missing_layers: Vec<String>,
    },

    /// The sandbox is not supported on this platform.
    #[error("sandbox requires Linux (current OS: {current_os})")]
    UnsupportedPlatform {
        /// Current operating system.
        current_os: String,
    },
}

// ---------------------------------------------------------------------------
// Policy errors
// ---------------------------------------------------------------------------

/// Errors from the policy engine and baseline store.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Failed to look up a baseline from the store.
    #[error("baseline lookup failed for {package}: {message}")]
    BaselineLookupFailed {
        /// Package identifier string.
        package: String,
        /// Error description.
        message: String,
    },

    /// Failed to persist a baseline update.
    #[error("baseline upsert failed for {package}: {message}")]
    BaselineUpsertFailed {
        /// Package identifier string.
        package: String,
        /// Error description.
        message: String,
    },

    /// The scoring configuration is invalid.
    #[error("invalid scoring config: {message}")]
    InvalidScoringConfig {
        /// Description of the configuration problem.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Audit errors
// ---------------------------------------------------------------------------

/// Errors from the audit logging layer.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to write to the audit log file.
    #[error("audit log write failed ({path}): {message}")]
    WriteFailed {
        /// Path to the audit log file.
        path: PathBuf,
        /// Error description.
        message: String,
    },

    /// HMAC signing of an audit entry failed.
    #[error("HMAC signing failed: {message}")]
    HmacError {
        /// Error description.
        message: String,
    },

    /// The audit log file is corrupted or has integrity issues.
    #[error("audit log integrity check failed ({path}): {message}")]
    IntegrityError {
        /// Path to the audit log file.
        path: PathBuf,
        /// Error description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Config errors
// ---------------------------------------------------------------------------

/// Errors from loading and validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be found.
    #[error("config file not found: {path}")]
    FileNotFound {
        /// Expected config file path.
        path: PathBuf,
    },

    /// The config file contains invalid TOML.
    #[error("TOML parse error in {path}: {message}")]
    ParseError {
        /// Config file path.
        path: PathBuf,
        /// Parser error message.
        message: String,
    },

    /// A required config field is missing.
    #[error("missing required config field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// A config value is out of the valid range.
    #[error("invalid value for {field}: {message}")]
    InvalidValue {
        /// Config field name.
        field: String,
        /// Description of why the value is invalid.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_error_displays_context() {
        let err = SafeguardError::Registry(RegistryError::NotFound {
            name: "evil-pkg".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
        });
        let msg = err.to_string();
        assert!(msg.contains("evil-pkg"));
        assert!(msg.contains("1.0.0"));
        assert!(msg.contains("npm"));
    }

    #[test]
    fn sandbox_partial_isolation_lists_layers() {
        let err = SandboxError::PartialIsolation {
            missing_layers: vec!["network".into(), "seccomp".into()],
        };
        let msg = err.to_string();
        assert!(msg.contains("network"));
        assert!(msg.contains("seccomp"));
        assert!(msg.contains("aborting"));
    }

    #[test]
    fn error_conversion_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: SafeguardError = io_err.into();
        assert!(matches!(err, SafeguardError::Io(_)));
    }
}
