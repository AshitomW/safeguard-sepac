//! Secret scanning analyser for credential harvest prevention.

use std::fs;
use std::path::{Path, PathBuf};

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyser for credential exfiltration and exposed secret patterns.
#[derive(Debug, Default)]
pub struct SecretScanningAnalyser;

impl SecretScanningAnalyser {
    /// Creates a new `SecretScanningAnalyser`.
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

impl Analyser for SecretScanningAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let mut files = Vec::new();
        collect_files(&pkg.extracted_path, Path::new(""), &mut files);

        for file_path in files {
            let full_path = pkg.extracted_path.join(&file_path);
            let metadata = match fs::metadata(&full_path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() > 1_000_000 {
                continue;
            }

            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_idx, line) in content.lines().enumerate() {
                let line_no = line_idx + 1;

                if line.contains("AWS_SECRET_ACCESS_KEY") || line.contains("AKIA") {
                    signals.push(Signal::SecretExposed {
                        file: file_path.clone(),
                        secret_type: "AWS Secret Access Key Pattern".into(),
                        line: line_no,
                    });
                } else if line.contains("GITHUB_TOKEN") || line.contains("ghp_") {
                    signals.push(Signal::SecretExposed {
                        file: file_path.clone(),
                        secret_type: "GitHub Access Token Pattern".into(),
                        line: line_no,
                    });
                } else if line.contains("NPM_TOKEN") || (line.contains("npm_") && line.len() > 30) {
                    signals.push(Signal::SecretExposed {
                        file: file_path.clone(),
                        secret_type: "NPM Auth Token Pattern".into(),
                        line: line_no,
                    });
                } else if line.contains("hooks.slack.com/services") {
                    signals.push(Signal::SecretExposed {
                        file: file_path.clone(),
                        secret_type: "Slack Incoming Webhook URL".into(),
                        line: line_no,
                    });
                } else if line.contains("-----BEGIN PRIVATE KEY-----")
                    || line.contains("-----BEGIN RSA PRIVATE KEY-----")
                {
                    signals.push(Signal::SecretExposed {
                        file: file_path.clone(),
                        secret_type: "PEM Private Key".into(),
                        line: line_no,
                    });
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
    fn secret_scanning_detects_aws_keys() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("preinstall.js");
        fs::write(&file_path, "const key = process.env.AWS_SECRET_ACCESS_KEY;").unwrap();

        let analyser = SecretScanningAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "test".into(),
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
            Signal::SecretExposed { secret_type, line, .. } => {
                assert!(secret_type.contains("AWS"));
                assert_eq!(*line, 1);
            }
            _ => panic!("expected SecretExposed signal"),
        }
    }
}
