//! Dependency confusion vulnerability analyser.

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyser for dependency confusion and version inflation attacks.
#[derive(Debug, Default)]
pub struct DependencyConfusionAnalyser;

impl DependencyConfusionAnalyser {
    /// Creates a new `DependencyConfusionAnalyser`.
    pub fn new() -> Self {
        Self
    }
}

impl Analyser for DependencyConfusionAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let name = &pkg.id.name;
        let version = &pkg.id.version;

        let mut version_jump = false;
        let mut internal_pattern = false;
        let mut reason_parts = Vec::new();

        // Check 1: Extreme version inflation (>100.0.0 or major version >= 50)
        let major = version
            .split('.')
            .next()
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(0);

        if major >= 50 {
            version_jump = true;
            reason_parts.push(format!("extreme version inflation v{version}"));
        }

        // Check 2: Org-scoped internal naming patterns (e.g. @cloudplatform-*, @internal-*, @corp-*)
        if name.starts_with('@') {
            let scope = name.split('/').next().unwrap_or("");
            if scope.contains("internal")
                || scope.contains("cloudplatform")
                || scope.contains("corp")
                || scope.contains("private")
                || scope.contains("baas")
                || scope.contains("single-spa")
            {
                internal_pattern = true;
                reason_parts.push(format!("internal org scope pattern '{scope}'"));
            }
        }

        if version_jump || internal_pattern {
            signals.push(Signal::DependencyConfusion {
                reason: reason_parts.join("; "),
                version_jump,
                internal_pattern,
            });
        }

        Ok(signals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ecosystem, PackageId, PackageManifest};
    use std::path::PathBuf;

    #[test]
    fn dependency_confusion_detects_version_inflation() {
        let analyser = DependencyConfusionAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "@cloudplatform-single-spa/svp-baas".into(),
                version: "100.100.100".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: PathBuf::from("/tmp/pkg"),
            manifest: PackageManifest::default(),
            tarball: vec![],
        };

        let signals = analyser.analyse(&pkg).unwrap();
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            Signal::DependencyConfusion { version_jump, internal_pattern, .. } => {
                assert!(*version_jump);
                assert!(*internal_pattern);
            }
            _ => panic!("expected DependencyConfusion signal"),
        }
    }
}
