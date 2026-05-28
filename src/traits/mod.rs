//! Core trait definitions for Safeguard.
//!
//! Every inter-layer dependency flows through the traits defined here.
//! No concrete type from one layer may appear in another layer's API —
//! only these traits or primitive types from [`crate::types`].

pub mod analyser;
pub mod baseline_store;
pub mod decision_policy;
pub mod executor;
pub mod logger;
pub mod package_source;
pub mod scorer;

pub use analyser::Analyser;
pub use baseline_store::BaselineStore;
pub use decision_policy::DecisionPolicy;
pub use executor::Executor;
pub use logger::Logger;
pub use package_source::PackageSource;
pub use scorer::Scorer;
