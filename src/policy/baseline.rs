//! In-memory baseline store.
//!
//! This module provides an `InMemoryBaselineStore` for testing and
//! development. A SQLite-backed store will be added in a later phase.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::traits::BaselineStore;
use crate::types::{Baseline, PackageId, Result};

/// An in-memory baseline store backed by a `HashMap`.
///
/// Suitable for testing and short-lived CLI runs where persistence
/// across invocations is not needed.
///
/// # Design
/// - Abstracts the storage backend.
/// - Thread-safe: Uses `Arc<RwLock<...>>` for concurrent access.
/// - Substitutable: Implements `BaselineStore`, droppable in for
///   any other backend without call-site changes.
#[derive(Debug, Clone, Default)]
pub struct InMemoryBaselineStore {
    store: Arc<RwLock<HashMap<PackageId, Baseline>>>,
}

impl InMemoryBaselineStore {
    /// Creates a new empty in-memory baseline store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BaselineStore for InMemoryBaselineStore {
    async fn get(&self, id: &PackageId) -> Result<Option<Baseline>> {
        let store = self.store.read().await;
        Ok(store.get(id).cloned())
    }

    async fn upsert(&self, id: &PackageId, baseline: &Baseline) -> Result<()> {
        let mut store = self.store.write().await;
        store.insert(id.clone(), baseline.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::Ecosystem;

    fn test_package_id() -> PackageId {
        PackageId {
            name: "test-pkg".into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Npm,
        }
    }

    fn test_baseline(pkg_id: &PackageId) -> Baseline {
        Baseline {
            package_id: pkg_id.clone(),
            known_syscalls: vec!["read".into(), "write".into(), "exit".into()],
            version_count: 5,
            updated_at: Utc::now(),
            known_signal_labels: vec![],
        }
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let store = InMemoryBaselineStore::new();
        let result = store.get(&test_package_id()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn upsert_then_get_returns_baseline() {
        let store = InMemoryBaselineStore::new();
        let id = test_package_id();
        let baseline = test_baseline(&id);

        store.upsert(&id, &baseline).await.unwrap();
        let result = store.get(&id).await.unwrap();

        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.version_count, 5);
        assert_eq!(retrieved.known_syscalls.len(), 3);
    }

    #[tokio::test]
    async fn upsert_overwrites_existing() {
        let store = InMemoryBaselineStore::new();
        let id = test_package_id();

        let baseline_v1 = test_baseline(&id);
        store.upsert(&id, &baseline_v1).await.unwrap();

        let mut baseline_v2 = test_baseline(&id);
        baseline_v2.version_count = 10;
        baseline_v2.known_syscalls.push("connect".into());
        store.upsert(&id, &baseline_v2).await.unwrap();

        let result = store.get(&id).await.unwrap().unwrap();
        assert_eq!(result.version_count, 10);
        assert_eq!(result.known_syscalls.len(), 4);
    }

    #[tokio::test]
    async fn different_packages_are_independent() {
        let store = InMemoryBaselineStore::new();

        let id1 = PackageId {
            name: "pkg-a".into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Npm,
        };
        let id2 = PackageId {
            name: "pkg-b".into(),
            version: "2.0.0".into(),
            ecosystem: Ecosystem::PyPi,
        };

        let baseline1 = test_baseline(&id1);
        store.upsert(&id1, &baseline1).await.unwrap();

        assert!(store.get(&id1).await.unwrap().is_some());
        assert!(store.get(&id2).await.unwrap().is_none());
    }
}
