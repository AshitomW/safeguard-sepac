//! YARA threat signature and custom pattern matching analyser.

use std::fs;
use std::path::{Path, PathBuf};

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// YARA rule pattern definition.
#[derive(Debug, Clone)]
pub struct YaraRule {
    /// Rule identifier.
    pub name: String,
    /// Target patterns to match.
    pub patterns: Vec<String>,
}

/// Analyser for custom YARA rules and threat pattern matching.
#[derive(Debug, Default)]
pub struct YaraAnalyser {
    /// Active rules.
    pub rules: Vec<YaraRule>,
}

impl YaraAnalyser {
    /// Creates a new `YaraAnalyser` with default built-in threat signatures.
    pub fn new() -> Self {
        Self {
            rules: vec![
                YaraRule {
                    name: "ReverseShell_Netcat".into(),
                    patterns: vec!["nc -e /bin/sh".into(), "nc -e /bin/bash".into()],
                },
                YaraRule {
                    name: "Discord_Webhook_Exfil".into(),
                    patterns: vec!["api/webhooks/".into(), "discord.com/api/webhooks".into()],
                },
                YaraRule {
                    name: "Crypto_Miner_Stratum".into(),
                    patterns: vec!["stratum+tcp://".into(), "stratum+ssl://".into()],
                },
            ],
        }
    }

    /// Loads additional YARA rules from a text file directory.
    pub fn load_rules_from_dir(&mut self, _dir: &PathBuf) {
        // Dynamic rule loader stub for safeguard.toml [yara.rules_path]
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

impl Analyser for YaraAnalyser {
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

            for rule in &self.rules {
                let mut matched_patterns = Vec::new();
                for pat in &rule.patterns {
                    if content.contains(pat) {
                        matched_patterns.push(pat.clone());
                    }
                }

                if !matched_patterns.is_empty() {
                    signals.push(Signal::YaraRuleMatch {
                        rule_name: rule.name.clone(),
                        file: file_path.clone(),
                        matches: matched_patterns,
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
    fn yara_threat_rule_matching() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("payload.js");
        fs::write(&file_path, "fetch('https://discord.com/api/webhooks/12345/abc');").unwrap();

        let analyser = YaraAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "discord-stealer".into(),
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
            Signal::YaraRuleMatch { rule_name, .. } => {
                assert_eq!(rule_name, "Discord_Webhook_Exfil");
            }
            _ => panic!("expected YaraRuleMatch signal"),
        }
    }
}
