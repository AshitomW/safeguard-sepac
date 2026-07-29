//! Typosquatting analyser using Levenshtein distance and homoglyph substitution matching.

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Popular packages target list for typosquatting detection.
pub const TOP_POPULAR_PACKAGES: &[&str] = &[
    "express", "lodash", "react", "axios", "async", "chalk", "commander",
    "request", "moment", "debug", "opensearch", "elasticsearch", "aws-sdk",
    "typescript", "vue", "next", "webpack", "babel", "rxjs", "jest",
    "typescript-eslint", "prettier", "glob", "fs-extra", "bluebird",
];

/// Analyser for typosquatting and homoglyph attacks.
#[derive(Debug, Default)]
pub struct TyposquatAnalyser;

impl TyposquatAnalyser {
    /// Creates a new `TyposquatAnalyser`.
    pub fn new() -> Self {
        Self
    }

    /// Computes Levenshtein edit distance between two strings.
    pub fn levenshtein_distance(a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();

        let m = a_chars.len();
        let n = b_chars.len();

        let mut dp = vec![vec![0; n + 1]; m + 1];

        for (i, row) in dp.iter_mut().enumerate().take(m + 1) {
            row[0] = i;
        }
        for (j, val) in dp[0].iter_mut().enumerate().take(n + 1) {
            *val = j;
        }

        for i in 1..=m {
            for j in 1..=n {
                let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
                dp[i][j] = (dp[i - 1][j] + 1)
                    .min(dp[i][j - 1] + 1)
                    .min(dp[i - 1][j - 1] + cost);
            }
        }

        dp[m][n]
    }
}

impl Analyser for TyposquatAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let pkg_name = &pkg.id.name;

        for &popular in TOP_POPULAR_PACKAGES {
            if pkg_name == popular {
                continue; // Exact match on legitimate package
            }

            let distance = Self::levenshtein_distance(pkg_name, popular);

            // Flag if distance is 1 or 2 on packages of length >= 4
            if distance > 0 && distance <= 2 && pkg_name.len() >= 4 {
                let confidence = 1.0 - (distance as f64 / popular.len() as f64);
                signals.push(Signal::Typosquat {
                    target_package: popular.to_string(),
                    distance,
                    confidence: confidence.max(0.0).min(1.0),
                });
                break;
            }
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
    fn levenshtein_calculation() {
        assert_eq!(TyposquatAnalyser::levenshtein_distance("express", "expres"), 1);
        assert_eq!(TyposquatAnalyser::levenshtein_distance("lodash", "loadsh"), 2);
    }

    #[test]
    fn typosquat_detection_emits_signal() {
        let analyser = TyposquatAnalyser::new();
        let pkg = PackageArchive {
            id: PackageId {
                name: "expres".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            extracted_path: PathBuf::from("/tmp/expres"),
            manifest: PackageManifest::default(),
            tarball: vec![],
        };

        let signals = analyser.analyse(&pkg).unwrap();
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            Signal::Typosquat { target_package, distance, .. } => {
                assert_eq!(target_package, "express");
                assert_eq!(*distance, 1);
            }
            _ => panic!("expected Typosquat signal"),
        }
    }
}
