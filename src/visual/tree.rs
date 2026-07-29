//! Dependency tree terminal visualization with risk heatmap coloring.

use std::fmt::Write as _;
use std::path::Path;

use crate::manifest::parse_manifest;
use crate::types::{DecisionTier, Ecosystem, PackageId, Result, RiskScore};

/// A node in the dependency tree with optional risk score annotation.
#[derive(Debug, Clone)]
pub struct DependencyNode {
    /// Package identity.
    pub package: PackageId,
    /// Risk score if evaluated.
    pub risk_score: Option<RiskScore>,
    /// Child dependencies.
    pub children: Vec<DependencyNode>,
}

/// Renders a dependency tree using terminal box-drawing characters and risk heatmaps.
#[derive(Debug, Default)]
pub struct TreeVisualizer {
    /// Enable ANSI color codes in output.
    use_color: bool,
}

impl TreeVisualizer {
    /// Creates a new `TreeVisualizer` with color settings.
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    /// Builds and formats a terminal dependency tree from a manifest file.
    pub fn render_manifest(&self, path: &Path, ecosystem: Ecosystem) -> Result<String> {
        let packages = parse_manifest(path, ecosystem)?;
        let root_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project");

        let children = packages
            .into_iter()
            .map(|pkg| DependencyNode {
                package: pkg,
                risk_score: None,
                children: Vec::new(),
            })
            .collect();

        let root = DependencyNode {
            package: PackageId {
                name: root_name.to_string(),
                version: "root".to_string(),
                ecosystem,
            },
            risk_score: Some(RiskScore::new(0)),
            children,
        };

        Ok(self.render_tree(&root))
    }

    /// Formats a `DependencyNode` hierarchy into a terminal string.
    pub fn render_tree(&self, root: &DependencyNode) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} {}",
            root.package.name,
            self.format_score(root.risk_score)
        );

        self.render_children(&mut out, &root.children, "");
        out
    }

    fn render_children(&self, out: &mut String, children: &[DependencyNode], prefix: &str) {
        let count = children.len();
        for (i, child) in children.iter().enumerate() {
            let is_last = i + 1 == count;
            let connector = if is_last { "└── " } else { "├── " };
            let child_prefix = if is_last { "    " } else { "│   " };

            let score_str = self.format_score(child.risk_score);
            let _ = writeln!(
                out,
                "{prefix}{connector}{}@{} {score_str}",
                child.package.name, child.package.version
            );

            let next_prefix = format!("{prefix}{child_prefix}");
            self.render_children(out, &child.children, &next_prefix);
        }
    }

    fn format_score(&self, score: Option<RiskScore>) -> String {
        let Some(s) = score else {
            return "[?]".to_string();
        };

        let tier = s.tier();
        let label = match tier {
            DecisionTier::Allow => "ALLOW",
            DecisionTier::Warn => "WARN",
            DecisionTier::Block => "BLOCK",
            DecisionTier::Critical => "CRITICAL",
        };

        if !self.use_color {
            return format!("[{label} {s}]");
        }

        let color_code = match tier {
            DecisionTier::Allow => "\x1b[32m",    // Green
            DecisionTier::Warn => "\x1b[33m",     // Yellow
            DecisionTier::Block => "\x1b[31m",    // Red
            DecisionTier::Critical => "\x1b[35m", // Magenta
        };
        let reset = "\x1b[0m";

        format!("{color_code}[{label} {s}]{reset}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_rendering_structure() {
        let root = DependencyNode {
            package: PackageId {
                name: "my-app".into(),
                version: "1.0.0".into(),
                ecosystem: Ecosystem::Npm,
            },
            risk_score: Some(RiskScore::new(0)),
            children: vec![
                DependencyNode {
                    package: PackageId {
                        name: "lodash".into(),
                        version: "4.17.21".into(),
                        ecosystem: Ecosystem::Npm,
                    },
                    risk_score: Some(RiskScore::new(2)),
                    children: vec![],
                },
                DependencyNode {
                    package: PackageId {
                        name: "express".into(),
                        version: "4.18.2".into(),
                        ecosystem: Ecosystem::Npm,
                    },
                    risk_score: Some(RiskScore::new(12)),
                    children: vec![],
                },
            ],
        };

        let viz = TreeVisualizer::new(false);
        let output = viz.render_tree(&root);

        assert!(output.contains("my-app"));
        assert!(output.contains("├── lodash@4.17.21 [ALLOW 2/20]"));
        assert!(output.contains("└── express@4.18.2 [BLOCK 12/20]"));
    }
}
