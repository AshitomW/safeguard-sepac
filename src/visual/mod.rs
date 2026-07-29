//! Visual inspection, terminal heatmaps, SBOM generation, and diff visualization.

pub mod diff;
pub mod sbom;
pub mod timeline;
pub mod tree;

pub use diff::{DiffVisualizer, PackageDiffReport};
pub use sbom::{SbomFormat, SbomGenerator};
pub use timeline::{PackageTimeline, TimelineEntry, TimelineVisualizer};
pub use tree::{DependencyNode, TreeVisualizer};
