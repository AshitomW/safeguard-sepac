//! Package version diff visualization.

use std::fmt::Write as _;

use crate::types::{PackageId, Signal};

/// Visual diff report comparing two package versions.
#[derive(Debug, Clone)]
pub struct PackageDiffReport {
    /// Target package ID for version 1.
    pub v1: PackageId,
    /// Target package ID for version 2.
    pub v2: PackageId,
    /// Maintainers in v1.
    pub v1_maintainers: Vec<String>,
    /// Maintainers in v2.
    pub v2_maintainers: Vec<String>,
    /// Install scripts in v1 (script_name -> command).
    pub v1_scripts: Vec<(String, String)>,
    /// Install scripts in v2 (script_name -> command).
    pub v2_scripts: Vec<(String, String)>,
    /// Signals emitted during version diff analysis.
    pub signals: Vec<Signal>,
}

/// Renderer for package version diffs.
#[derive(Debug, Default)]
pub struct DiffVisualizer {
    /// Enable ANSI color codes.
    use_color: bool,
}

impl DiffVisualizer {
    /// Creates a new `DiffVisualizer`.
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    /// Renders a side-by-side terminal diff string for a `PackageDiffReport`.
    pub fn render(&self, report: &PackageDiffReport) -> String {
        let mut out = String::new();

        let red = if self.use_color { "\x1b[31m" } else { "" };
        let green = if self.use_color { "\x1b[32m" } else { "" };
        let bold = if self.use_color { "\x1b[1m" } else { "" };
        let reset = if self.use_color { "\x1b[0m" } else { "" };

        let _ = writeln!(
            out,
            "{bold}Package Version Diff: {} (v{} -> v{}){reset}\n",
            report.v1.name, report.v1.version, report.v2.version
        );

        // Maintainer diff
        let _ = writeln!(out, "{bold}Maintainer Changes:{reset}");
        if report.v1_maintainers == report.v2_maintainers {
            let _ = writeln!(out, "  No maintainer changes detected.");
        } else {
            for m in &report.v1_maintainers {
                if !report.v2_maintainers.contains(m) {
                    let _ = writeln!(out, "  {red}- {m}{reset}");
                }
            }
            for m in &report.v2_maintainers {
                if !report.v1_maintainers.contains(m) {
                    let _ = writeln!(out, "  {green}+ {m} (NEW MAINTAINER){reset}");
                }
            }
        }
        let _ = writeln!(out);

        // Lifecycle script diff
        let _ = writeln!(out, "{bold}Lifecycle Scripts:{reset}");
        let v1_keys: Vec<_> = report.v1_scripts.iter().map(|(k, _)| k).collect();
        let v2_keys: Vec<_> = report.v2_scripts.iter().map(|(k, _)| k).collect();

        if report.v1_scripts == report.v2_scripts {
            let _ = writeln!(out, "  No script changes.");
        } else {
            for (k, v) in &report.v1_scripts {
                if !v2_keys.contains(&k) {
                    let _ = writeln!(out, "  {red}- {k}: {v}{reset}");
                }
            }
            for (k, v) in &report.v2_scripts {
                if !v1_keys.contains(&k) {
                    let _ = writeln!(out, "  {green}+ {k}: {v} (NEW SCRIPT){reset}");
                } else if let Some((_, old_v)) = report.v1_scripts.iter().find(|(name, _)| name == k)
                {
                    if old_v != v {
                        let _ = writeln!(out, "  {red}- {k}: {old_v}{reset}");
                        let _ = writeln!(out, "  {green}+ {k}: {v}{reset}");
                    }
                }
            }
        }
        let _ = writeln!(out);

        // Signals summary
        let _ = writeln!(out, "{bold}Diff Risk Signals ({}) :{reset}", report.signals.len());
        if report.signals.is_empty() {
            let _ = writeln!(out, "  Clean diff — zero risk signals.");
        } else {
            for sig in &report.signals {
                let _ = writeln!(out, "  {red}* [{}] {}{reset}", sig.label(), sig.detail());
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ecosystem;

    #[test]
    fn diff_rendering_output() {
        let report = PackageDiffReport {
            v1: PackageId {
                name: "demo".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            v2: PackageId {
                name: "demo".into(),
                version: "1.0.1".into(),
                ecosystem: Ecosystem::Npm,
            },
            v1_maintainers: vec!["alice@example.com".into()],
            v2_maintainers: vec!["alice@example.com".into(), "evil@attacker.com".into()],
            v1_scripts: vec![],
            v2_scripts: vec![("postinstall".into(), "node inject.js".into())],
            signals: vec![Signal::PostInstallAdded {
                previous_versions_without: 1,
            }],
        };

        let viz = DiffVisualizer::new(false);
        let out = viz.render(&report);

        assert!(out.contains("Package Version Diff: demo (v1.0.0 -> v1.0.1)"));
        assert!(out.contains("+ evil@attacker.com (NEW MAINTAINER)"));
        assert!(out.contains("+ postinstall: node inject.js (NEW SCRIPT)"));
        assert!(out.contains("* [post-install-added]"));
    }
}
