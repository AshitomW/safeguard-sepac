//! Continuous lockfile watcher for automated supply-chain monitoring.

use std::path::PathBuf;

use crate::manifest::parse_manifest;
use crate::types::{Ecosystem, Result};

/// Daemon monitoring configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Directory to watch for lockfile changes.
    pub watch_dir: PathBuf,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
}

/// Continuous lockfile daemon watcher.
pub struct LockfileWatcher {
    config: DaemonConfig,
}

impl LockfileWatcher {
    /// Creates a new `LockfileWatcher`.
    pub fn new(config: DaemonConfig) -> Self {
        Self { config }
    }

    /// Scans lockfiles currently present in the target watch directory.
    pub fn scan_target_dir(&self) -> Result<Vec<(PathBuf, Ecosystem, usize)>> {
        let mut results = Vec::new();

        let lockfiles = [
            ("package-lock.json", Ecosystem::Npm),
            ("Cargo.lock", Ecosystem::Cargo),
            ("requirements.txt", Ecosystem::PyPi),
            ("Gemfile.lock", Ecosystem::RubyGems),
        ];

        for (filename, eco) in &lockfiles {
            let target_path = self.config.watch_dir.join(filename);
            if target_path.exists() {
                if let Ok(packages) = parse_manifest(&target_path, *eco) {
                    results.push((target_path, *eco, packages.len()));
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn daemon_watcher_scans_lockfile() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{"name":"test","lockfileVersion":2,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();

        let config = DaemonConfig {
            watch_dir: dir.path().to_path_buf(),
            poll_interval_secs: 5,
        };

        let watcher = LockfileWatcher::new(config);
        let results = watcher.scan_target_dir().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, Ecosystem::Npm);
        assert_eq!(results[0].2, 1);
    }
}
