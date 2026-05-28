//! Mock sandbox executor — always available on all platforms.
//!
//! Returns configurable `SyscallLog` for testing. Implements the
//! `Executor` trait and is substitutable per the Liskov Substitution
//! Principle — any call site expecting `dyn Executor` works identically
//! with `MockExecutor`.

use async_trait::async_trait;

use crate::config::SandboxConfig;
use crate::traits::Executor;
use crate::types::{PackageArchive, Result, SyscallLog};

/// A mock executor that returns a pre-configured `SyscallLog`.
///
/// # Design
/// - **Liskov Substitution**: Droppable in for the real `SandboxExecutor`
///   at every call site without behaviour change.
/// - **Configurable**: Test code sets the expected output via builder methods.
/// - **Platform-independent**: No Linux dependencies.
#[derive(Debug, Clone, Default)]
pub struct MockExecutor {
    /// The syscall log to return from `execute()`.
    response: SyscallLog,
}

impl MockExecutor {
    /// Creates a new mock executor that returns an empty syscall log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the syscall log to return from `execute()`.
    pub fn with_response(mut self, response: SyscallLog) -> Self {
        self.response = response;
        self
    }
}

#[async_trait]
impl Executor for MockExecutor {
    async fn execute(&self, _pkg: &PackageArchive, _config: &SandboxConfig) -> Result<SyscallLog> {
        Ok(self.response.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{Ecosystem, PackageId, PackageManifest, SyscallEntry};

    fn test_package() -> PackageArchive {
        PackageArchive {
            id: PackageId {
                name: "test-pkg".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: PathBuf::from("/tmp/test"),
            manifest: PackageManifest::default(),
            tarball: vec![],
        }
    }

    #[tokio::test]
    async fn mock_returns_empty_log_by_default() {
        let executor = MockExecutor::new();
        let config = SandboxConfig::default();
        let log = executor.execute(&test_package(), &config).await.unwrap();
        assert!(log.entries.is_empty());
        assert!(!log.killed_by_seccomp);
    }

    #[tokio::test]
    async fn mock_returns_configured_response() {
        let response = SyscallLog {
            entries: vec![SyscallEntry {
                name: "connect".into(),
                args: "AF_INET, 1.2.3.4:443".into(),
                return_code: -1,
                elapsed_ms: 10,
            }],
            duration_ms: 100,
            killed_by_seccomp: true,
            kill_signal: Some(31),
        };

        let executor = MockExecutor::new().with_response(response);
        let config = SandboxConfig::default();
        let log = executor.execute(&test_package(), &config).await.unwrap();

        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].name, "connect");
        assert!(log.killed_by_seccomp);
        assert_eq!(log.kill_signal, Some(31));
    }
}
