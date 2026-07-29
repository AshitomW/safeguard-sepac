//! Policy engine: scoring, decisions, baselines, rego policies, and signal aggregation.

pub mod aggregator;
pub mod baseline;
pub mod decision;
pub mod rego;
pub mod scorer;
pub mod sqlite_baseline;

pub use rego::{PolicyEngine, PolicyRule};
pub use sqlite_baseline::SqliteBaselineStore;
