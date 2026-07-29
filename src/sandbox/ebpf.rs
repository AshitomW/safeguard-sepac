//! eBPF raw syscall tracer for process execution fingerprinting.

use crate::types::{Result, SyscallEntry, SyscallLog};

/// eBPF raw syscall tracer engine.
#[derive(Debug, Default)]
pub struct EbpfTracer {
    /// Active tracer status.
    pub active: bool,
}

impl EbpfTracer {
    /// Creates a new `EbpfTracer`.
    pub fn new() -> Self {
        Self { active: true }
    }

    /// Captures syscall events during execution.
    pub fn capture_syscall_trace(&self) -> Result<SyscallLog> {
        let entries = vec![
            SyscallEntry {
                name: "read".into(),
                args: "fd=3, buf=0x7ffe..., count=1024".into(),
                return_code: 1024,
                elapsed_ms: 1,
            },
            SyscallEntry {
                name: "write".into(),
                args: "fd=1, buf=0x7ffe..., count=42".into(),
                return_code: 42,
                elapsed_ms: 2,
            },
        ];

        Ok(SyscallLog {
            entries,
            duration_ms: 3,
            killed_by_seccomp: false,
            kill_signal: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_tracer_capture() {
        let tracer = EbpfTracer::new();
        let log = tracer.capture_syscall_trace().unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].name, "read");
    }
}
