//! CI environment reconnaissance and sandbox bypass analyser.

use std::fs;
use std::path::{Path, PathBuf};

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyser for CI environment reset, reconnaissance mode, and sandbox bypass flags.
#[derive(Debug, Default)]
pub struct CIEnvironmentAnalyser;

impl CIEnvironmentAnalyser {
    /// Creates a new `CIEnvironmentAnalyser`.
    pub fn new() -> Self {
        Self
    }
}

fn collect_files(dir: &Path, rel_prefix: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = rel_prefix.join(entry.file_name());
            if path.is_dir() {
                collect_files(&path, &rel, out);
            } else if path.is_file() {
                out.push(rel);
            }
        }
    }
}

impl Analyser for CIEnvironmentAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let mut files = Vec::new();
        collect_files(&pkg.extracted_path, Path::new(""), &mut files);

        for file_path in files {
            let full_path = pkg.extracted_path.join(&file_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                if line.contains("CI=false")
                    || line.contains("process.env.CI = 'false'")
                    || line.contains("process.env.CI=\"false\"")
                {
                    signals.push(Signal::CIAttack {
                        file: file_path.clone(),
                        flag_found: "CI=false reset".into(),
                    });
                    break;
                } else if line.contains("RECON_ONLY") {
                    signals.push(Signal::CIAttack {
                        file: file_path.clone(),
                        flag_found: "RECON_ONLY reconnaissance mode".into(),
                    });
                    break;
                } else if line.contains("DISABLE_TELEMETRY") || line.contains("NO_TELEMETRY") {
                    signals.push(Signal::CIAttack {
                        file: file_path.clone(),
                        flag_found: "NO_TELEMETRY override".into(),
                    });
                    break;
                }
            }
        }

        Ok(signals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ecosystem, PackageId, PackageManifest};
    use tempfile::tempdir;

    #[test]
    fn ci_attack_flag_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("setup.js");
        fs::write(&file_path, "process.env.CI = 'false';").unwrap();

        let analyser = CIEnvironmentAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "miasma-worm".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: dir.path().to_path_buf(),
            manifest: PackageManifest::default(),
            tarball: vec![],
        };

        let signals = analyser.analyse(&pkg).unwrap();
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            Signal::CIAttack { flag_found, .. } => {
                assert!(flag_found.contains("CI=false"));
            }
            _ => panic!("expected CIAttack signal"),
        }
    }
}
