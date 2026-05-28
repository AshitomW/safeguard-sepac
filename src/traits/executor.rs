//! The `Executor` trait — runs install scripts inside a hardened sandbox.
//!
//! The executor is responsible for setting up all isolation layers
//! (network ns, mount ns, user ns, seccomp-bpf) and capturing the
//! syscall fingerprint via eBPF.

use async_trait::async_trait;

use crate::config::SandboxConfig;
use crate::types::{PackageArchive, Result, SyscallLog};

/// Executes package install scripts inside a hardened sandbox.
///
/// # Responsibilities
/// - Setting up all four isolation layers (or aborting)
/// - Running install scripts in the sandboxed environment
/// - Capturing the syscall trace via eBPF
/// - Enforcing timeouts and resource limits
///
/// # Invariant
/// All four isolation layers must succeed or the executor must abort.
/// Partial isolation is a fatal error — see [`crate::error::SandboxError::PartialIsolation`].
#[async_trait]
pub trait Executor: Send + Sync {
    /// Executes the package's install scripts in a sandbox.
    ///
    /// Returns the complete syscall log captured during execution.
    /// The sandbox config controls which isolation layers are enabled
    /// and their parameters.
    async fn execute(&self, pkg: &PackageArchive, config: &SandboxConfig) -> Result<SyscallLog>;
}
