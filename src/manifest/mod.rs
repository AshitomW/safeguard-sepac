//! Manifest and lockfile parsing for dependency resolution.

use std::path::Path;

use crate::error::{AnalysisError, SafeguardError};
use crate::types::{Ecosystem, PackageId, Result};

/// Parses a package manager manifest or lockfile to extract dependencies.
///
/// Supports:
/// - `package.json` (direct dependencies with range-cleaning fallback)
/// - `package-lock.json` (exact direct and transitive dependency locks)
pub fn parse_manifest(path: &Path, ecosystem: Ecosystem) -> Result<Vec<PackageId>> {
    match ecosystem {
        Ecosystem::Npm => parse_npm_manifest(path),
        _ => Err(SafeguardError::Analysis(AnalysisError::UnsupportedFormat {
            format: format!("{:?}", ecosystem),
            file: path.to_path_buf(),
        })),
    }
}

/// Parses npm package.json or package-lock.json files.
fn parse_npm_manifest(path: &Path) -> Result<Vec<PackageId>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SafeguardError::Io(std::io::Error::other(format!(
            "failed to read manifest file {}: {e}",
            path.display()
        )))
    })?;

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut packages = Vec::new();

    if file_name.contains("lock") {
        // Parse package-lock.json
        let lock: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            SafeguardError::Analysis(AnalysisError::ParseError {
                file: path.to_path_buf(),
                message: format!("invalid package-lock.json: {e}"),
            })
        })?;

        if let Some(packages_obj) = lock.get("packages").and_then(|p| p.as_object()) {
            // npm v7+ lockfile format
            for (p_path, p_info) in packages_obj {
                if p_path.is_empty() {
                    continue; // Root package
                }
                let leaf_name = if let Some(idx) = p_path.rfind("node_modules/") {
                    &p_path[idx + "node_modules/".len()..]
                } else {
                    p_path
                };

                if let Some(version) = p_info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.starts_with("http") && !v.starts_with("git") && !v.contains('/'))
                {
                    packages.push(PackageId {
                        name: leaf_name.to_string(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Npm,
                    });
                }
            }
        } else if let Some(dependencies_obj) = lock.get("dependencies").and_then(|d| d.as_object())
        {
            // npm v5/v6 lockfile format
            for (name, p_info) in dependencies_obj {
                if let Some(version) = p_info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.starts_with("http") && !v.starts_with("git") && !v.contains('/'))
                {
                    packages.push(PackageId {
                        name: name.clone(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Npm,
                    });
                }
            }
        }
    } else {
        // Parse package.json
        let pkg: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            SafeguardError::Analysis(AnalysisError::ParseError {
                file: path.to_path_buf(),
                message: format!("invalid package.json: {e}"),
            })
        })?;

        let mut add_deps = |deps_val: &serde_json::Value| {
            if let Some(deps_obj) = deps_val.as_object() {
                for (name, version_spec) in deps_obj {
                    if let Some(version) = version_spec.as_str() {
                        let clean_ver = version
                            .replace(['^', '~', '>', '=', '<'], "")
                            .split("||")
                            .next()
                            .unwrap_or(version)
                            .trim()
                            .to_string();

                        if !clean_ver.is_empty()
                            && !clean_ver.starts_with("http")
                            && !clean_ver.starts_with("git")
                            && !clean_ver.contains('/')
                        {
                            packages.push(PackageId {
                                name: name.clone(),
                                version: clean_ver,
                                ecosystem: Ecosystem::Npm,
                            });
                        }
                    }
                }
            }
        };

        if let Some(deps) = pkg.get("dependencies") {
            add_deps(deps);
        }
        if let Some(dev_deps) = pkg.get("devDependencies") {
            add_deps(dev_deps);
        }
    }

    // Sort and deduplicate
    packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    packages.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn parse_valid_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");

        let content = r#"{
            "name": "test-app",
            "dependencies": {
                "express": "^4.19.2",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "typescript": "5.4.5",
                "local-git": "git+https://github.com/user/repo.git"
            }
        }"#;

        std::fs::write(&path, content).unwrap();

        let packages = parse_manifest(&path, Ecosystem::Npm).unwrap();
        assert_eq!(packages.len(), 3);

        assert_eq!(packages[0].name, "express");
        assert_eq!(packages[0].version, "4.19.2");

        assert_eq!(packages[1].name, "lodash");
        assert_eq!(packages[1].version, "4.17.21");

        assert_eq!(packages[2].name, "typescript");
        assert_eq!(packages[2].version, "5.4.5");
    }

    #[test]
    fn parse_valid_package_lock_v7_plus() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package-lock.json");

        let content = r#"{
            "name": "test-app",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {
                        "express": "4.19.2"
                    }
                },
                "node_modules/express": {
                    "version": "4.19.2",
                    "dependencies": {
                        "send": "0.18.0"
                    }
                },
                "node_modules/express/node_modules/send": {
                    "version": "0.18.0"
                }
            }
        }"#;

        std::fs::write(&path, content).unwrap();

        let packages = parse_manifest(&path, Ecosystem::Npm).unwrap();
        assert_eq!(packages.len(), 2);

        assert_eq!(packages[0].name, "express");
        assert_eq!(packages[0].version, "4.19.2");

        assert_eq!(packages[1].name, "send");
        assert_eq!(packages[1].version, "0.18.0");
    }

    #[test]
    fn parse_unsupported_ecosystem_fails() {
        let path = PathBuf::from("Cargo.toml");
        let result = parse_manifest(&path, Ecosystem::Cargo);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SafeguardError::Analysis(AnalysisError::UnsupportedFormat { .. })
        ));
    }
}
