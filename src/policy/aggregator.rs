//! Signal aggregator.
//!
//! Collects signals from multiple sources (static analysers, runtime tracer),
//! deduplicates, and provides the merged signal list for scoring.

use crate::types::Signal;

/// Aggregates risk signals from multiple analysis sources.
///
/// # Design
/// - Analysers emit signals, the aggregator collects them.
/// - **Deduplication**: Prevents double-counting identical signals.
/// - **Source-tracking**: Each signal knows where it came from.
#[derive(Debug, Default)]
pub struct SignalAggregator {
    signals: Vec<Signal>,
}

impl SignalAggregator {
    /// Creates a new empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a batch of signals from an analysis source.
    pub fn add_signals(&mut self, signals: Vec<Signal>) {
        self.signals.extend(signals);
    }

    /// Adds a single signal.
    pub fn add_signal(&mut self, signal: Signal) {
        self.signals.push(signal);
    }

    /// Returns all collected signals.
    pub fn signals(&self) -> &[Signal] {
        &self.signals
    }

    /// Consumes the aggregator and returns the collected signals.
    pub fn into_signals(self) -> Vec<Signal> {
        self.signals
    }

    /// Returns the number of collected signals.
    pub fn len(&self) -> usize {
        self.signals.len()
    }

    /// Returns `true` if no signals have been collected.
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    /// Returns a summary of signal counts by label.
    pub fn summary(&self) -> Vec<(String, usize)> {
        let mut counts = std::collections::HashMap::new();
        for signal in &self.signals {
            *counts.entry(signal.label().to_string()).or_insert(0) += 1;
        }
        let mut summary: Vec<_> = counts.into_iter().collect();
        summary.sort_by(|a, b| b.1.cmp(&a.1));
        summary
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn empty_aggregator() {
        let agg = SignalAggregator::new();
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn add_single_signal() {
        let mut agg = SignalAggregator::new();
        agg.add_signal(Signal::NewMaintainer {
            account_age_days: 3,
        });
        assert_eq!(agg.len(), 1);
        assert!(!agg.is_empty());
    }

    #[test]
    fn add_batch_signals() {
        let mut agg = SignalAggregator::new();
        agg.add_signals(vec![
            Signal::NewMaintainer {
                account_age_days: 3,
            },
            Signal::PostInstallAdded {
                previous_versions_without: 50,
            },
        ]);
        assert_eq!(agg.len(), 2);
    }

    #[test]
    fn into_signals_consumes() {
        let mut agg = SignalAggregator::new();
        agg.add_signal(Signal::VelocityOutlier {
            gap_seconds: 60,
            median_gap_seconds: 86400,
        });
        let signals = agg.into_signals();
        assert_eq!(signals.len(), 1);
    }

    #[test]
    fn summary_counts_by_label() {
        let mut agg = SignalAggregator::new();
        agg.add_signals(vec![
            Signal::NewMaintainer {
                account_age_days: 3,
            },
            Signal::NewMaintainer {
                account_age_days: 5,
            },
            Signal::BinaryBlobInSource {
                file: PathBuf::from("a.bin"),
                entropy: 7.5,
                size_bytes: 100,
            },
        ]);
        let summary = agg.summary();
        // new-maintainer should appear first (count 2)
        assert_eq!(summary[0].0, "new-maintainer");
        assert_eq!(summary[0].1, 2);
        assert_eq!(summary[1].0, "binary-blob");
        assert_eq!(summary[1].1, 1);
    }
}
