//! Risk timeline graph and historical velocity visualization.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};

use crate::types::{PackageId, RiskScore};

/// A single version release snapshot in a package's history.
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    /// Package version string.
    pub version: String,
    /// Release timestamp.
    pub published_at: DateTime<Utc>,
    /// Maintainer account that published the release.
    pub maintainer: String,
    /// Computed risk score for this release (if analyzed).
    pub risk_score: Option<RiskScore>,
    /// Release gap from previous version in seconds.
    pub gap_seconds: Option<u64>,
}

/// Historical package risk timeline model.
#[derive(Debug, Clone)]
pub struct PackageTimeline {
    /// Package identity.
    pub package: PackageId,
    /// Chronological list of releases.
    pub releases: Vec<TimelineEntry>,
}

/// Renderer for package risk timelines.
#[derive(Debug, Default)]
pub struct TimelineVisualizer {
    use_color: bool,
}

impl TimelineVisualizer {
    /// Creates a new `TimelineVisualizer`.
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    /// Formats a `PackageTimeline` into a terminal risk trend graph.
    pub fn render(&self, timeline: &PackageTimeline) -> String {
        let mut out = String::new();

        let bold = if self.use_color { "\x1b[1m" } else { "" };
        let reset = if self.use_color { "\x1b[0m" } else { "" };

        let _ = writeln!(
            out,
            "{bold}Risk & Velocity Timeline: {} ({}){reset}\n",
            timeline.package.name, timeline.package.ecosystem
        );

        let _ = writeln!(
            out,
            "VERSION      PUBLISHED AT          MAINTAINER            GAP        RISK SCORE"
        );
        let _ = writeln!(
            out,
            "-------------------------------------------------------------------------------"
        );

        for entry in &timeline.releases {
            let score_str = match entry.risk_score {
                Some(s) => self.format_score_bar(s),
                None => "[?]".to_string(),
            };

            let gap_str = match entry.gap_seconds {
                Some(g) if g < 3600 => format!("{g}s (FAST)"),
                Some(g) => format!("{}h", g / 3600),
                None => "initial".to_string(),
            };

            let date_str = entry.published_at.format("%Y-%m-%d %H:%M").to_string();
            let _ = writeln!(
                out,
                "{:<12} {:<21} {:<21} {:<10} {}",
                entry.version, date_str, entry.maintainer, gap_str, score_str
            );
        }

        out
    }

    fn format_score_bar(&self, score: RiskScore) -> String {
        let val = score.value() as usize;
        let bar_filled = "█".repeat(val);
        let bar_empty = "░".repeat(20 - val);

        if !self.use_color {
            return format!("[{bar_filled}{bar_empty}] ({val}/20)");
        }

        let color = match val {
            0..=4 => "\x1b[32m",   // Green
            5..=9 => "\x1b[33m",   // Yellow
            10..=14 => "\x1b[31m",  // Red
            _ => "\x1b[35m",       // Magenta
        };
        let reset = "\x1b[0m";

        format!("{color}[{bar_filled}{bar_empty}]{reset} ({val}/20)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ecosystem;

    #[test]
    fn timeline_rendering() {
        let timeline = PackageTimeline {
            package: PackageId {
                name: "express".into(),
                version: "4.18.2".into(),
                ecosystem: Ecosystem::Npm,
            },
            releases: vec![
                TimelineEntry {
                    version: "4.18.1".into(),
                    published_at: Utc::now(),
                    maintainer: "alice".into(),
                    risk_score: Some(RiskScore::new(0)),
                    gap_seconds: None,
                },
                TimelineEntry {
                    version: "4.18.2".into(),
                    published_at: Utc::now(),
                    maintainer: "bob".into(),
                    risk_score: Some(RiskScore::new(12)),
                    gap_seconds: Some(120),
                },
            ],
        };

        let viz = TimelineVisualizer::new(false);
        let out = viz.render(&timeline);

        assert!(out.contains("Risk & Velocity Timeline: express (npm)"));
        assert!(out.contains("4.18.2"));
        assert!(out.contains("120s (FAST)"));
    }
}
