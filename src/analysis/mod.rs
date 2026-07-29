//! Static analysis layer.
//!
//! Analyses packages for attack indicators using
//! manifest diffing, obfuscation detection, typosquatting, secrets,
//! dependency confusion, sigstore attestations, and a composable pipeline.

pub mod ci_attack;
pub mod dep_confusion;
pub mod import_exec;
pub mod manifest_diff;
pub mod obfuscation;
pub mod phantom_gyp;
pub mod pipeline;
pub mod secrets;
pub mod sigstore;
pub mod typosquat;
pub mod yara;

pub use ci_attack::CIEnvironmentAnalyser;
pub use dep_confusion::DependencyConfusionAnalyser;
pub use import_exec::ImportTimePayloadAnalyser;
pub use manifest_diff::ManifestDiffAnalyser;
pub use obfuscation::ObfuscationAnalyser;
pub use phantom_gyp::PhantomGypAnalyser;
pub use pipeline::AnalysisPipeline;
pub use secrets::SecretScanningAnalyser;
pub use sigstore::SigstoreVerifier;
pub use typosquat::TyposquatAnalyser;
pub use yara::YaraAnalyser;
