//! Safeguard — package-manager-agnostic attack prevention.
//!
//! This crate provides the core library for intercepting package manager
//! install commands, analysing packages for attack indicators,
//! executing install scripts in hardened sandboxes, and making risk-based
//! allow/warn/block decisions.
//!
//! # Architecture
//!
//! The system is organised in layers, each communicating through traits:
//!
//! ```text
//! CLI shim (per-ecosystem, thin — clap + tokio)
//! RegistryAdapter (trait object — one impl per ecosystem)
//! ─────────────────────────────── abstraction boundary
//! StaticAnalyser (AST diff, manifest diff, obfuscation scorer)
//! SandboxExecutor (namespace orchestration, seccomp-bpf, eBPF)
//! PolicyEngine (baseline lookup, signal aggregation)
//! RiskScorer (weighted additive model, threshold tiers)
//! DecisionGate (trust-mode aware — Paranoid / Balanced / YOLO)
//! AuditLogger (append-only, signed, SIEM-ready JSON)
//! ```
//!
//! # Core Traits
//!
//! - [`traits::PackageSource`] — fetch packages from registries
//! - [`traits::Analyser`] — static analysis of package contents
//! - [`traits::Executor`] — sandbox execution of install scripts
//! - [`traits::BaselineStore`] — historical baseline persistence
//! - [`traits::Scorer`] — risk score computation
//! - [`traits::DecisionPolicy`] — allow/warn/block decisions
//! - [`traits::Logger`] — signed audit log entries

pub mod analysis;
pub mod audit;
pub mod config;
pub mod error;
pub mod manifest;
pub mod policy;
pub mod registry;
pub mod sandbox;
pub mod traits;
pub mod types;
