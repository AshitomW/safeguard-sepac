//! Policy engine: scoring, decisions, baselines, and signal aggregation.
//!
//! This layer is purely computational — no I/O, no filesystem, no network.
//! Every component receives its inputs as function arguments and returns
//! deterministic outputs.

pub mod aggregator;
pub mod baseline;
pub mod decision;
pub mod scorer;
