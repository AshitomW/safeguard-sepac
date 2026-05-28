//! Static analysis layer.
//!
//! Analyses packages for attack indicators using
//! manifest diffing, obfuscation detection, and a composable pipeline.

pub mod manifest_diff;
pub mod obfuscation;
pub mod pipeline;
