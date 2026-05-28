//! Manifest-level diff analyser.
//!
//! Compares the current package manifest against a previous version's
//! manifest to detect attack indicators: new install scripts,
//! maintainer changes, unexpected dependency additions.

use crate::traits::Analyser;
use crate::types::{PackageArchive, PackageManifest, Result, Signal};

/// Analyses manifest-level changes between package versions.
///
/// # Detected signals
/// - `PostInstallAdded`: A post-install script was added.
/// - `DependencyAdded`: A new dependency was introduced.
/// - `NewMaintainer`: A new maintainer appeared.
///
/// # Design
/// - Single responsibility: manifest structure only (no source code).
/// - Implements `Analyser` so it can be composed/chained.
pub struct ManifestDiffAnalyser {
    /// The previous version's manifest to diff against.
    /// If `None`, all current scripts/deps are treated as new.
    previous_manifest: Option<PackageManifest>,
}

impl ManifestDiffAnalyser {
    /// Creates a new analyser with an optional previous manifest for comparison.
    pub fn new(previous_manifest: Option<PackageManifest>) -> Self {
        Self { previous_manifest }
    }

    /// Checks for newly added install scripts.
    fn check_install_scripts(&self, current: &PackageManifest) -> Vec<Signal> {
        let previous_script_count = self
            .previous_manifest
            .as_ref()
            .map_or(0, |m| m.install_scripts.len());

        if !current.install_scripts.is_empty() && previous_script_count == 0 {
            vec![Signal::PostInstallAdded {
                previous_versions_without: 1,
            }]
        } else {
            vec![]
        }
    }

    /// Checks for newly added dependencies.
    fn check_new_dependencies(&self, current: &PackageManifest) -> Vec<Signal> {
        let previous_deps = self
            .previous_manifest
            .as_ref()
            .map_or_else(Default::default, |m| m.dependencies.clone());

        current
            .dependencies
            .iter()
            .filter(|(name, _)| !previous_deps.contains_key(*name))
            .map(|(name, version)| Signal::DependencyAdded {
                dependency_name: name.clone(),
                version_constraint: version.clone(),
            })
            .collect()
    }

    /// Checks for new maintainers.
    fn check_new_maintainers(&self, current: &PackageManifest) -> Vec<Signal> {
        let previous_maintainers = self
            .previous_manifest
            .as_ref()
            .map_or_else(Vec::new, |m| m.maintainers.clone());

        current
            .maintainers
            .iter()
            .filter(|m| !previous_maintainers.contains(m))
            .map(|_| Signal::NewMaintainer {
                // In a real implementation, we'd look up account age from the registry.
                // For now, we flag the signal and let the scorer weight it.
                account_age_days: 0,
            })
            .collect()
    }
}

impl Analyser for ManifestDiffAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();

        signals.extend(self.check_install_scripts(&pkg.manifest));
        signals.extend(self.check_new_dependencies(&pkg.manifest));
        signals.extend(self.check_new_maintainers(&pkg.manifest));

        Ok(signals)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{Ecosystem, InstallScript, PackageId};

    fn test_package(manifest: PackageManifest) -> PackageArchive {
        PackageArchive {
            id: PackageId {
                name: "test".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: PathBuf::from("/tmp/test"),
            manifest,
            tarball: vec![],
        }
    }

    #[test]
    fn no_previous_manifest_flags_new_scripts() {
        let mut manifest = PackageManifest::default();
        manifest.install_scripts.push(InstallScript {
            phase: "postinstall".into(),
            command: "node exploit.js".into(),
        });

        let analyser = ManifestDiffAnalyser::new(None);
        let signals = analyser.analyse(&test_package(manifest)).unwrap();

        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::PostInstallAdded { .. }))
        );
    }

    #[test]
    fn existing_scripts_not_flagged() {
        let mut prev = PackageManifest::default();
        prev.install_scripts.push(InstallScript {
            phase: "postinstall".into(),
            command: "echo done".into(),
        });

        let mut current = PackageManifest::default();
        current.install_scripts.push(InstallScript {
            phase: "postinstall".into(),
            command: "echo done".into(),
        });

        let analyser = ManifestDiffAnalyser::new(Some(prev));
        let signals = analyser.analyse(&test_package(current)).unwrap();

        assert!(
            !signals
                .iter()
                .any(|s| matches!(s, Signal::PostInstallAdded { .. }))
        );
    }

    #[test]
    fn new_dependency_detected() {
        let prev = PackageManifest::default();
        let mut current = PackageManifest::default();
        current
            .dependencies
            .insert("evil-dep".into(), "^1.0.0".into());

        let analyser = ManifestDiffAnalyser::new(Some(prev));
        let signals = analyser.analyse(&test_package(current)).unwrap();

        assert!(signals.iter().any(|s| matches!(
            s,
            Signal::DependencyAdded { dependency_name, .. } if dependency_name == "evil-dep"
        )));
    }

    #[test]
    fn new_maintainer_detected() {
        let mut prev = PackageManifest::default();
        prev.maintainers.push("trusted-dev".into());

        let mut current = PackageManifest::default();
        current.maintainers.push("trusted-dev".into());
        current.maintainers.push("new-suspicious-dev".into());

        let analyser = ManifestDiffAnalyser::new(Some(prev));
        let signals = analyser.analyse(&test_package(current)).unwrap();

        assert!(
            signals
                .iter()
                .any(|s| matches!(s, Signal::NewMaintainer { .. }))
        );
    }

    #[test]
    fn clean_package_emits_no_signals() {
        let prev = PackageManifest::default();
        let current = PackageManifest::default();

        let analyser = ManifestDiffAnalyser::new(Some(prev));
        let signals = analyser.analyse(&test_package(current)).unwrap();

        assert!(signals.is_empty());
    }
}
