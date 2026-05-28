//! The `BaselineStore` trait — persistence for historical baselines.
//!
//! Concrete backends include SQLite (for production) and in-memory (for testing).

use async_trait::async_trait;

use crate::types::{Baseline, PackageId, Result};

/// Persists and retrieves historical syscall/signal baselines for packages.
///
/// # Responsibilities
/// - Storing baselines keyed by package identity
/// - Retrieving baselines for comparison during analysis
/// - Upserting baselines as new versions are analysed
///
/// # Design
/// The store is an abstracted persistence layer (can be swapped).
/// Consumers never know whether the backend is SQLite, in-memory, or
/// a remote service.
#[async_trait]
pub trait BaselineStore: Send + Sync {
    /// Retrieves the baseline for a package, if one exists.
    ///
    /// Returns `Ok(None)` if no baseline has been recorded yet.
    async fn get(&self, id: &PackageId) -> Result<Option<Baseline>>;

    /// Creates or updates the baseline for a package.
    async fn upsert(&self, id: &PackageId, baseline: &Baseline) -> Result<()>;
}
