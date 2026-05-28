//! Sandbox execution layer.
//!
//! The real sandbox (namespace orchestration, seccomp-bpf, eBPF) is
//! Linux-only. This module provides the mock executor that is always
//! available for testing and development on any platform.

pub mod mock;
