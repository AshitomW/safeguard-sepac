//! Analysis pipeline.
//!
//! Chains multiple `Analyser` implementations and collects all signals.
//! Each analyser runs independently and contributes its signals to the
//! aggregate result.

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Chains multiple analysers into a pipeline.
///
/// Each analyser runs independently. The pipeline collects all signals
/// from all analysers into a single `Vec<Signal>`.
///
/// # Design
/// - Each analyser processes the package
///   and contributes signals without knowledge of other analysers.
/// - **Open/Closed**: New analysers can be added to the pipeline without
///   modifying existing ones.
pub struct AnalysisPipeline {
    analysers: Vec<Box<dyn Analyser>>,
}

impl AnalysisPipeline {
    /// Creates a new empty pipeline.
    pub fn new() -> Self {
        Self {
            analysers: Vec::new(),
        }
    }

    /// Adds an analyser to the pipeline.
    pub fn add_analyser(mut self, analyser: Box<dyn Analyser>) -> Self {
        self.analysers.push(analyser);
        self
    }

    /// Creates a pipeline populated with all default built-in static analysers.
    pub fn default_pipeline() -> Self {
        Self::new()
            .add_analyser(Box::new(super::manifest_diff::ManifestDiffAnalyser::new(None)))
            .add_analyser(Box::new(super::obfuscation::ObfuscationAnalyser::new()))
            .add_analyser(Box::new(super::typosquat::TyposquatAnalyser::new()))
            .add_analyser(Box::new(super::dep_confusion::DependencyConfusionAnalyser::new()))
            .add_analyser(Box::new(super::secrets::SecretScanningAnalyser::new()))
            .add_analyser(Box::new(super::import_exec::ImportTimePayloadAnalyser::new()))
            .add_analyser(Box::new(super::ci_attack::CIEnvironmentAnalyser::new()))
            .add_analyser(Box::new(super::phantom_gyp::PhantomGypAnalyser::new()))
            .add_analyser(Box::new(super::yara::YaraAnalyser::new()))
    }

    /// Runs all analysers and collects their signals.
    pub fn run(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut all_signals = Vec::new();
        for analyser in &self.analysers {
            let signals = analyser.analyse(pkg)?;
            all_signals.extend(signals);
        }
        Ok(all_signals)
    }
}

impl Default for AnalysisPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{Ecosystem, PackageId, PackageManifest};

    /// A test analyser that always returns a fixed set of signals.
    struct FixedSignalAnalyser {
        signals: Vec<Signal>,
    }

    impl Analyser for FixedSignalAnalyser {
        fn analyse(&self, _pkg: &PackageArchive) -> Result<Vec<Signal>> {
            Ok(self.signals.clone())
        }
    }

    fn test_package() -> PackageArchive {
        PackageArchive {
            id: PackageId {
                name: "test".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: PathBuf::from("/nonexistent"),
            manifest: PackageManifest::default(),
            tarball: vec![],
        }
    }

    #[test]
    fn empty_pipeline_returns_no_signals() {
        let pipeline = AnalysisPipeline::new();
        let signals = pipeline.run(&test_package()).unwrap();
        assert!(signals.is_empty());
    }

    #[test]
    fn single_analyser_signals_collected() {
        let pipeline = AnalysisPipeline::new().add_analyser(Box::new(FixedSignalAnalyser {
            signals: vec![Signal::NewMaintainer {
                account_age_days: 1,
            }],
        }));
        let signals = pipeline.run(&test_package()).unwrap();
        assert_eq!(signals.len(), 1);
    }

    #[test]
    fn multiple_analysers_signals_merged() {
        let pipeline = AnalysisPipeline::new()
            .add_analyser(Box::new(FixedSignalAnalyser {
                signals: vec![Signal::NewMaintainer {
                    account_age_days: 1,
                }],
            }))
            .add_analyser(Box::new(FixedSignalAnalyser {
                signals: vec![
                    Signal::PostInstallAdded {
                        previous_versions_without: 10,
                    },
                    Signal::VelocityOutlier {
                        gap_seconds: 60,
                        median_gap_seconds: 86400,
                    },
                ],
            }));
        let signals = pipeline.run(&test_package()).unwrap();
        assert_eq!(signals.len(), 3);
    }

    #[test]
    fn analyser_returning_no_signals_is_fine() {
        let pipeline = AnalysisPipeline::new()
            .add_analyser(Box::new(FixedSignalAnalyser { signals: vec![] }))
            .add_analyser(Box::new(FixedSignalAnalyser {
                signals: vec![Signal::ProvenanceMissing {
                    expected: "Sigstore".into(),
                }],
            }));
        let signals = pipeline.run(&test_package()).unwrap();
        assert_eq!(signals.len(), 1);
    }
}
