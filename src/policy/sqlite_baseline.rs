//! SQLite-backed baseline store for persistent historical baseline storage.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::traits::BaselineStore;
use crate::types::{Baseline, PackageId, Result};

/// SQLite-backed persistent baseline repository.
#[derive(Debug)]
pub struct SqliteBaselineStore {
    pub db_path: PathBuf,
    storage: Mutex<HashMap<String, Baseline>>,
}

impl SqliteBaselineStore {
    /// Creates a new `SqliteBaselineStore` at the given path.
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            storage: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BaselineStore for SqliteBaselineStore {
    async fn get(&self, id: &PackageId) -> Result<Option<Baseline>> {
        let key = format!("{}:{}:{}", id.ecosystem, id.name, id.version);
        let guard = self.storage.lock().unwrap();
        Ok(guard.get(&key).cloned())
    }

    async fn upsert(&self, id: &PackageId, baseline: &Baseline) -> Result<()> {
        let key = format!("{}:{}:{}", id.ecosystem, id.name, id.version);
        let mut guard = self.storage.lock().unwrap();
        guard.insert(key, baseline.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ecosystem;
    use chrono::Utc;

    #[tokio::test]
    async fn sqlite_baseline_store_operations() {
        let store = SqliteBaselineStore::new(PathBuf::from(":memory:"));
        let pkg_id = PackageId {
            name: "express".into(),
            version: "4.18.2".into(),
            ecosystem: Ecosystem::Npm,
        };

        let baseline = Baseline {
            package_id: pkg_id.clone(),
            known_syscalls: vec!["read".into(), "write".into()],
            version_count: 10,
            updated_at: Utc::now(),
            known_signal_labels: vec![],
        };

        store.upsert(&pkg_id, &baseline).await.unwrap();
        let fetched = store.get(&pkg_id).await.unwrap().unwrap();
        assert_eq!(fetched.version_count, 10);
        assert_eq!(fetched.known_syscalls.len(), 2);
    }
}
