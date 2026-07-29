//! Sandbox execution layer.
//!
//! Provides native Linux hardening (namespace orchestration, seccomp-bpf, eBPF)
//! as well as mock executors for unit testing.

pub mod ebpf;
pub mod linux;
pub mod mock;

pub use ebpf::EbpfTracer;
pub use linux::LinuxSandboxExecutor;
pub use mock::MockExecutor;

use crate::config::SandboxConfig;
use crate::traits::Executor;

/// Factory for creating platform-appropriate sandbox executors.
pub struct SandboxExecutorFactory;

impl SandboxExecutorFactory {
    /// Creates a sandbox executor based on target OS and sandbox configuration.
    pub fn for_config(config: &SandboxConfig) -> Box<dyn Executor> {
        if cfg!(target_os = "linux") || config.is_fully_isolated() {
            Box::new(LinuxSandboxExecutor::new())
        } else {
            Box::new(MockExecutor::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_creates_sandbox_executor() {
        let config = SandboxConfig::default();
        let _executor = SandboxExecutorFactory::for_config(&config);
    }
}
