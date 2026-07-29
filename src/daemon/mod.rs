//! Daemon service for continuous background security monitoring.

pub mod watcher;

pub use watcher::{DaemonConfig, LockfileWatcher};
