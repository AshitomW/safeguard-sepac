//! The `Analyser` trait — performs static analysis on a package.
//!
//! Analysers emit typed [`Signal`]s that are fed into the risk scorer.
//! Multiple analysers can be chained in a pipeline.

use crate::types::{PackageArchive, Result, Signal};

/// Performs static analysis on a package archive and emits risk signals.
///
/// # Responsibilities
/// - AST-level diffing between versions
/// - Manifest-level change detection
/// - Obfuscation scoring
/// - Provenance verification
///
/// # Design
/// Each analyser has one focus area. Multiple analysers are composed
/// in a pipeline — each runs independently
/// and contributes its signals to the aggregate.
pub trait Analyser: Send + Sync {
    /// Analyses the package and returns zero or more risk signals.
    ///
    /// An empty `Vec` means no issues were detected by this analyser.
    /// This method is synchronous — analysis is CPU-bound work that
    /// runs in a rayon thread pool, not the async runtime.
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>>;
}
