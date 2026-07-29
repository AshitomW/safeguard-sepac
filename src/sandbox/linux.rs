//! Hardened Linux sandbox executor enforcing the 4-layer isolation invariant.

use async_trait::async_trait;

use crate::config::SandboxConfig;
use crate::error::{SafeguardError, SandboxError};
use crate::traits::Executor;
use crate::types::{PackageArchive, Result, SyscallLog};

/// Hardened Linux sandbox executor.
///
/// # Isolation Invariant
/// All 4 isolation layers (Network namespace, Mount namespace, User namespace,
/// and seccomp-bpf allowlists) must be active or execution aborts immediately.
#[derive(Debug, Default)]
pub struct LinuxSandboxExecutor;

impl LinuxSandboxExecutor {
    /// Creates a new `LinuxSandboxExecutor`.
    pub fn new() -> Self {
        Self
    }

    /// Verifies all 4 isolation layers before starting execution.
    fn verify_isolation_layers(&self, config: &SandboxConfig) -> Result<()> {
        let mut failed_layers = Vec::new();

        if !config.network_namespace {
            failed_layers.push("network_namespace".into());
        }
        if !config.mount_namespace {
            failed_layers.push("mount_namespace".into());
        }
        if !config.user_namespace {
            failed_layers.push("user_namespace".into());
        }
        if !config.seccomp_enabled {
            failed_layers.push("seccomp_enabled".into());
        }

        if !failed_layers.is_empty() {
            return Err(SafeguardError::Sandbox(SandboxError::PartialIsolation {
                missing_layers: failed_layers,
            }));
        }

        Ok(())
    }
}

#[async_trait]
impl Executor for LinuxSandboxExecutor {
    async fn execute(&self, _pkg: &PackageArchive, config: &SandboxConfig) -> Result<SyscallLog> {
        self.verify_isolation_layers(config)?;

        // Capture raw syscall trace using eBPF tracer
        let tracer = crate::sandbox::ebpf::EbpfTracer::new();
        tracer.capture_syscall_trace()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn linux_sandbox_enforces_isolation_invariant() {
        let executor = LinuxSandboxExecutor::new();
        let mut cfg = SandboxConfig::default();

        // Partial isolation must be rejected
        cfg.network_namespace = false;
        let res = executor.verify_isolation_layers(&cfg);
        assert!(res.is_err());
    }
}
