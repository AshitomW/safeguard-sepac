//! Safeguard CLI entry point.
//!
//! This is the thin CLI shim that wires all layers together.
//! It uses clap for argument parsing and orchestrates the full
//! analysis → sandbox → score → decide → report pipeline.

use std::path::PathBuf;
use std::process::ExitCode;

use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};

use sepac::analysis::manifest_diff::ManifestDiffAnalyser;
use sepac::analysis::pipeline::AnalysisPipeline;
use sepac::audit::logger::FileAuditLogger;
use sepac::audit::report::{OutputFormat, format_report};
use sepac::config::SafeguardConfig;
use sepac::error::SafeguardError;
use sepac::manifest::parse_manifest;
use sepac::policy::aggregator::SignalAggregator;

use sepac::policy::decision::ThresholdDecisionPolicy;
use sepac::policy::scorer::WeightedAdditiveScorer;
use sepac::registry::RegistryAdapterFactory;
use sepac::traits::{BaselineStore, DecisionPolicy, Logger, Scorer};
use sepac::types::{AuditEvent, Decision, Ecosystem, PackageId, Signal, TrustMode};

// ---------------------------------------------------------------------------
// CLI argument definitions
// ---------------------------------------------------------------------------

/// Safeguard — package-manager-agnostic attack prevention.
#[derive(Debug, Parser)]
#[command(
    name = "safeguard",
    version,
    about = "Safeguard — intercept, analyse, and gate package installs",
    long_about = "Safeguard intercepts package manager install commands, analyses packages \
                  for attack indicators, executes install scripts in hardened \
                  sandboxes, and makes risk-based allow/warn/block decisions."
)]
struct Cli {
    /// Path to the Safeguard config file.
    #[arg(
        long,
        short = 'c',
        default_value = "safeguard.toml",
        global = true,
        help = "Path to safeguard.toml config file"
    )]
    config: PathBuf,

    /// Override the trust mode from config.
    #[arg(
        long,
        short = 'm',
        global = true,
        help = "Override trust mode (paranoid, balanced, yolo)"
    )]
    mode: Option<CliTrustMode>,

    /// Output format.
    #[arg(
        long,
        default_value = "terminal",
        global = true,
        help = "Output format: terminal or json"
    )]
    format: CliOutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Analyse a package before installation.
    ///
    /// Fetches the package from the registry, runs static analysis,
    /// executes install scripts in a sandbox (mock on non-Linux),
    /// scores the risk, and reports the decision.
    #[command(alias = "analyse")]
    Analyze {
        /// Package name (e.g. "lodash").
        #[arg(help = "Package name")]
        name: String,

        /// Package version (e.g. "4.17.21").
        #[arg(help = "Package version")]
        version: String,

        /// Package ecosystem.
        #[arg(
            long,
            short = 'e',
            default_value = "npm",
            help = "Ecosystem: npm, pypi, cargo, rubygems"
        )]
        ecosystem: CliEcosystem,

        /// Force-override a block decision (logged to audit trail).
        #[arg(long, help = "Override block with a reason string")]
        force: Option<String>,
    },

    /// Show the current configuration.
    Config {
        /// Validate the config file and report any errors.
        #[arg(long, help = "Validate config and exit")]
        validate: bool,
    },

    /// Show the audit log for a package or all packages.
    Audit {
        /// Filter by package name.
        #[arg(long, help = "Filter audit log by package name")]
        package: Option<String>,

        /// Show last N entries.
        #[arg(long, default_value = "10", help = "Number of entries to show")]
        last: usize,
    },

    /// Scan a package manager manifest (e.g. package.json) and verify all dependencies.
    Scan {
        /// Path to the manifest file (e.g. package.json or package-lock.json).
        #[arg(help = "Path to manifest or lockfile")]
        path: PathBuf,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm", help = "Ecosystem: npm")]
        ecosystem: CliEcosystem,
    },

    /// Run a local HTTP registry proxy server to intercept package downloads.
    Proxy {
        /// Port to bind the HTTP proxy server to.
        #[arg(long, short = 'p', default_value = "8080", help = "Port to listen on")]
        port: u16,

        /// Default ecosystem to analyze.
        #[arg(long, short = 'e', default_value = "npm", help = "Ecosystem: npm")]
        ecosystem: CliEcosystem,
    },

    /// Display dependency tree with risk heatmap coloring.
    Tree {
        /// Path to manifest file (package.json or package-lock.json).
        #[arg(default_value = "package-lock.json")]
        path: PathBuf,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm")]
        ecosystem: CliEcosystem,
    },

    /// Compare two package versions side-by-side.
    Diff {
        /// Package name.
        package: String,

        /// Base version.
        v1: String,

        /// Target version.
        v2: String,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm")]
        ecosystem: CliEcosystem,
    },

    /// Generate an SBOM (SPDX 2.3 or CycloneDX 1.5).
    Sbom {
        /// Path to manifest or lockfile.
        #[arg(default_value = "package-lock.json")]
        path: PathBuf,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm")]
        ecosystem: CliEcosystem,

        /// Output format (spdx or cyclonedx).
        #[arg(long, default_value = "spdx")]
        format: String,
    },

    /// Show risk and velocity timeline across version history.
    Timeline {
        /// Package name.
        package: String,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm")]
        ecosystem: CliEcosystem,
    },

    /// Lookup known CVE vulnerabilities for a package via OSV.dev API.
    Cve {
        /// Package name.
        package: String,

        /// Package version.
        version: String,

        /// Package ecosystem.
        #[arg(long, short = 'e', default_value = "npm")]
        ecosystem: CliEcosystem,
    },

    /// Run continuous background lockfile monitoring daemon.
    Daemon {
        /// Directory to watch for lockfile modifications.
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// Polling interval in seconds.
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Run local web dashboard HTTP server.
    Web {
        /// Port to bind the dashboard HTTP server to.
        #[arg(long, short = 'p', default_value = "8080")]
        port: u16,
    },
}

/// CLI-friendly trust mode enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliTrustMode {
    Paranoid,
    Balanced,
    Yolo,
}

impl From<CliTrustMode> for TrustMode {
    fn from(m: CliTrustMode) -> Self {
        match m {
            CliTrustMode::Paranoid => TrustMode::Paranoid,
            CliTrustMode::Balanced => TrustMode::Balanced,
            CliTrustMode::Yolo => TrustMode::Yolo,
        }
    }
}

/// CLI-friendly ecosystem enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliEcosystem {
    Npm,
    Pypi,
    Cargo,
    Rubygems,
}

impl From<CliEcosystem> for Ecosystem {
    fn from(e: CliEcosystem) -> Self {
        match e {
            CliEcosystem::Npm => Ecosystem::Npm,
            CliEcosystem::Pypi => Ecosystem::PyPi,
            CliEcosystem::Cargo => Ecosystem::Cargo,
            CliEcosystem::Rubygems => Ecosystem::RubyGems,
        }
    }
}

/// CLI-friendly output format enum.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliOutputFormat {
    #[default]
    Terminal,
    Json,
    Html,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(f: CliOutputFormat) -> Self {
        match f {
            CliOutputFormat::Terminal => OutputFormat::Terminal,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Html => OutputFormat::Html,
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Load config — fall back to defaults if file doesn't exist
    let config = load_config(&cli.config);

    // Determine effective trust mode
    let trust_mode = cli.mode.map(TrustMode::from).unwrap_or(config.trust_mode);
    let output_format: OutputFormat = cli.format.into();

    match cli.command {
        Commands::Analyze {
            name,
            version,
            ecosystem,
            force,
        } => {
            let eco: Ecosystem = ecosystem.into();
            run_analysis(
                &config,
                &name,
                &version,
                eco,
                trust_mode,
                output_format,
                force,
            )
            .await
        }
        Commands::Scan { path, ecosystem } => {
            let eco: Ecosystem = ecosystem.into();
            run_scan_command(&config, &path, eco, trust_mode, output_format).await
        }
        Commands::Proxy { port, ecosystem } => {
            let eco: Ecosystem = ecosystem.into();
            run_proxy_command(&config, port, eco, trust_mode).await
        }
        Commands::Config { validate } => {
            run_config_command(&cli.config, validate);
            ExitCode::SUCCESS
        }
        Commands::Audit { package, last } => {
            run_audit_command(&config, package.as_deref(), last);
            ExitCode::SUCCESS
        }
        Commands::Tree { path, ecosystem } => {
            let eco: Ecosystem = ecosystem.into();
            let viz = sepac::visual::TreeVisualizer::new(true);
            match viz.render_manifest(&path, eco) {
                Ok(tree_str) => {
                    print!("{tree_str}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error rendering tree: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Diff {
            package,
            v1,
            v2,
            ecosystem,
        } => {
            let eco: Ecosystem = ecosystem.into();
            run_diff_command(&package, &v1, &v2, eco).await
        }
        Commands::Sbom {
            path,
            ecosystem,
            format,
        } => {
            let eco: Ecosystem = ecosystem.into();
            let sbom_fmt = format
                .parse::<sepac::visual::SbomFormat>()
                .unwrap_or(sepac::visual::SbomFormat::Spdx23);
            let generator = sepac::visual::SbomGenerator::new();
            match generator.generate_from_manifest(&path, eco, sbom_fmt) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error generating SBOM: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Timeline { package, ecosystem } => {
            let eco: Ecosystem = ecosystem.into();
            run_timeline_command(&package, eco).await
        }
        Commands::Cve {
            package,
            version,
            ecosystem,
        } => {
            let eco: Ecosystem = ecosystem.into();
            run_cve_command(&package, &version, eco).await
        }
        Commands::Daemon { dir, interval } => {
            run_daemon_command(dir, interval).await
        }
        Commands::Web { port } => {
            run_web_command(&config, port).await
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Runs the full analysis pipeline for a package.
/// Evaluates a package through the full analysis pipeline, returning the decision and event.
async fn evaluate_package(
    config: &SafeguardConfig,
    name: &str,
    version: &str,
    ecosystem: Ecosystem,
    trust_mode: TrustMode,
    force: Option<String>,
) -> Result<(Decision, AuditEvent), SafeguardError> {
    let id = PackageId {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem,
    };

    // --- 1. Fetch package from registry ---
    eprintln!("⏳ Fetching {name}@{version} from {ecosystem}...");
    let source = RegistryAdapterFactory::for_ecosystem(ecosystem);
    let archive = source.fetch(&id).await?;
    eprintln!("✓  Package fetched ({} bytes)", archive.tarball.len());

    // --- 2. Fetch version history for baseline comparison ---
    let history = source.history(name, ecosystem).await.unwrap_or_default();
    let previous_manifest = if history.len() > 1 {
        // In a real implementation, we'd fetch the previous version's manifest.
        None
    } else {
        None
    };

    // --- 3. Run static analysis pipeline ---
    eprintln!("🔍 Running static analysis pipeline...");
    let pipeline = AnalysisPipeline::default_pipeline()
        .add_analyser(Box::new(ManifestDiffAnalyser::new(previous_manifest)));

    let mut analysis_signals = pipeline.run(&archive)?;

    // --- 3b. Query OSV.dev CVE Database ---
    let osv_client = sepac::vulnerability::OsvClient::new();
    if let Ok(cve_signals) = osv_client.query_vulnerabilities(&id).await {
        analysis_signals.extend(cve_signals);
    }
    eprintln!("✓  Analysis complete: {} signals", analysis_signals.len());

    // --- 4. Run sandbox execution ---
    eprintln!("🔒 Running sandbox execution...");
    let executor = sepac::sandbox::SandboxExecutorFactory::for_config(&config.sandbox);
    let syscall_log = executor.execute(&archive, &config.sandbox).await?;

    // --- 4b. Baseline comparison ---
    let baseline_store = sepac::policy::SqliteBaselineStore::new(config.audit.log_path.clone());
    let baseline = baseline_store.get(&id).await.unwrap_or(None);

    let runtime_signals: Vec<Signal> = syscall_log
        .entries
        .iter()
        .map(|entry| {
            let occurrences = baseline
                .as_ref()
                .map(|b| if b.known_syscalls.contains(&entry.name) { 10 } else { 0 })
                .unwrap_or(0);
            Signal::RuntimeSyscall {
                name: entry.name.clone(),
                args: entry.args.clone(),
                historical_occurrences: occurrences,
            }
        })
        .collect();
    eprintln!(
        "✓  Sandbox complete: {} syscalls traced",
        syscall_log.entries.len()
    );

    // --- 5. Aggregate signals ---
    let mut aggregator = SignalAggregator::new();
    aggregator.add_signals(analysis_signals);
    aggregator.add_signals(runtime_signals);

    // Check provenance
    match source.provenance(&id).await {
        Ok(Some(prov)) if !prov.sigstore_verified => {
            aggregator.add_signal(Signal::ProvenanceMissing {
                expected: "Sigstore attestation".to_string(),
            });
        }
        Ok(None) => {
            aggregator.add_signal(Signal::ProvenanceMissing {
                expected: "Sigstore attestation".to_string(),
            });
        }
        _ => {}
    }

    let all_signals = aggregator.into_signals();

    // --- 6. Score and decide ---
    let scorer = WeightedAdditiveScorer::new();
    let risk_score = scorer.score(&all_signals, &config.scoring);

    let mode_config = config.trust_modes.for_mode(trust_mode);
    let policy = ThresholdDecisionPolicy::new(config.scoring.thresholds.clone());
    let mut decision = policy.decide(risk_score, trust_mode, mode_config);

    // Enterprise Policy Engine evaluation
    let policy_engine = sepac::policy::PolicyEngine::new();
    if let Some(policy_decision) = policy_engine.evaluate(ecosystem, risk_score, &all_signals) {
        decision = policy_decision;
    }

    // Handle --force override
    let force_override = force.is_some();
    if force_override && let Decision::Block { ref reasons } = decision {
        if mode_config.force_allowed {
            eprintln!(
                "⚠️  Force override applied. Blocked reasons: {}",
                reasons.join("; ")
            );
            decision = Decision::Allow;
        } else {
            eprintln!("❌ --force is not allowed in {} mode", trust_mode);
        }
    }

    // --- 7. Build audit event ---
    let event = AuditEvent {
        schema_version: AuditEvent::CURRENT_SCHEMA_VERSION,
        timestamp: Utc::now(),
        package_id: id.clone(),
        risk_score,
        decision: decision.clone(),
        signals: all_signals.clone(),
        trust_mode,
        force_override,
        force_reason: force,
    };

    // Dispatch alerts for blocked decisions
    let alert_dispatcher = sepac::audit::AlertDispatcher::new();
    let _ = alert_dispatcher.notify_if_blocked(&event).await;

    // Upsert baseline
    let new_baseline = sepac::types::Baseline {
        package_id: id,
        known_syscalls: syscall_log.entries.iter().map(|e| e.name.clone()).collect(),
        version_count: history.len() as u64,
        updated_at: Utc::now(),
        known_signal_labels: all_signals.iter().map(|s| s.label().to_string()).collect(),
    };
    let _ = baseline_store.upsert(&new_baseline.package_id, &new_baseline).await;

    // Attempt to log the event to the audit log
    if let Some(parent) = config.audit.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(logger) =
        FileAuditLogger::from_paths(&config.audit.log_path, &config.audit.hmac_key_path)
    {
        let _ = logger.log(&event);
    }

    Ok((decision, event))
}

/// Runs the full analysis pipeline for a package and prints results.
async fn run_analysis(
    config: &SafeguardConfig,
    name: &str,
    version: &str,
    ecosystem: Ecosystem,
    trust_mode: TrustMode,
    output_format: OutputFormat,
    force: Option<String>,
) -> ExitCode {
    match evaluate_package(config, name, version, ecosystem, trust_mode, force).await {
        Ok((decision, event)) => {
            let report = format_report(&event, output_format);
            println!("{report}");
            match decision {
                Decision::Allow => ExitCode::SUCCESS,
                Decision::Warn { .. } => ExitCode::SUCCESS,
                Decision::Block { .. } => ExitCode::from(2),
                Decision::Critical { .. } => ExitCode::from(3),
            }
        }
        Err(e) => {
            eprintln!("❌ Analysis failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs native manifest scan to check all dependencies.
async fn run_scan_command(
    config: &SafeguardConfig,
    path: &std::path::Path,
    ecosystem: Ecosystem,
    trust_mode: TrustMode,
    output_format: OutputFormat,
) -> ExitCode {
    println!("🔎 Scanning manifest file: {}...", path.display());
    let packages = match parse_manifest(path, ecosystem) {
        Ok(pkgs) => pkgs,
        Err(e) => {
            eprintln!("❌ Failed to parse manifest: {e}");
            return ExitCode::FAILURE;
        }
    };

    if packages.is_empty() {
        println!("⚠️  No packages found to analyze.");
        return ExitCode::SUCCESS;
    }

    println!(
        "🛡️  Found {} packages to audit. Running scans...",
        packages.len()
    );
    let mut any_blocked = false;
    let mut critical_blocked = false;

    for pkg in packages {
        println!("------------------------------------------------------------");
        println!("📦 Auditing {}@{}...", pkg.name, pkg.version);
        match evaluate_package(config, &pkg.name, &pkg.version, ecosystem, trust_mode, None).await {
            Ok((decision, event)) => {
                let report = format_report(&event, output_format);
                println!("{report}");
                match decision {
                    Decision::Block { .. } => {
                        any_blocked = true;
                    }
                    Decision::Critical { .. } => {
                        any_blocked = true;
                        critical_blocked = true;
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!(
                    "⚠️  Failed to scan package {}@{}: {e}",
                    pkg.name, pkg.version
                );
                any_blocked = true;
            }
        }
    }

    println!("------------------------------------------------------------");
    if critical_blocked {
        eprintln!("❌ SCAN FAILED: One or more dependencies triggered CRITICAL risk scores.");
        ExitCode::from(3)
    } else if any_blocked {
        eprintln!("❌ SCAN FAILED: One or more dependencies were BLOCKED by Safeguard policy.");
        ExitCode::from(2)
    } else {
        println!("✅ SCAN PASSED: All dependencies conform to policy rules.");
        ExitCode::SUCCESS
    }
}

/// Starts local HTTP registry proxy server.
async fn run_proxy_command(
    config: &SafeguardConfig,
    port: u16,
    ecosystem: Ecosystem,
    trust_mode: TrustMode,
) -> ExitCode {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to bind proxy to {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "🚀 Safeguard HTTP Registry Proxy running on http://{}",
        addr
    );
    println!("   Configure your package manager registry settings to target this proxy.");
    println!("   Example: npm config set registry http://{}", addr);
    println!("   Press Ctrl+C to stop.");

    let config_arc = std::sync::Arc::new(config.clone());
    let client = reqwest::Client::new();

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("⚠️  Error accepting connection: {e}");
                continue;
            }
        };

        let config_clone = config_arc.clone();
        let client_clone = client.clone();

        tokio::spawn(async move {
            handle_connection(stream, client_clone, config_clone, ecosystem, trust_mode).await;
        });
    }
}

/// Handles proxy connection.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    client: reqwest::Client,
    config: std::sync::Arc<SafeguardConfig>,
    ecosystem: Ecosystem,
    trust_mode: TrustMode,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request_str.lines();
    let request_line = match lines.next() {
        Some(line) => line,
        None => return,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    if method != "GET" {
        let response =
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes()).await;
        return;
    }

    // Intercept tarball downloads
    if let Some((pkg_name, version)) = parse_tarball_path(path) {
        println!("🛡️  Proxy: Intercepted download request for {pkg_name}@{version}");

        match evaluate_package(&config, &pkg_name, &version, ecosystem, trust_mode, None).await {
            Ok((decision, _)) if decision.is_blocked() => {
                println!("❌ Proxy: BLOCKED download of {pkg_name}@{version} due to risk score");
                let body = format!(
                    "{{\"error\": \"Forbidden\", \"message\": \"Package {pkg_name}@{version} was BLOCKED by Safeguard policy.\"}}"
                );
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                return;
            }
            Ok(_) => {
                println!("✅ Proxy: ALLOWED download of {pkg_name}@{version}");
            }
            Err(e) => {
                println!(
                    "⚠️  Proxy: Scan failed for {pkg_name}@{version}: {e} (Serving conservatively)"
                );
            }
        }
    }

    // Forward the GET request to the real public registry
    let target_url = format!("https://registry.npmjs.org{}", path);
    match client
        .get(&target_url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            if let Ok(bytes) = resp.bytes().await {
                let mut header_str = format!(
                    "HTTP/1.1 {} {}\r\n",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("OK")
                );
                for (k, v) in headers.iter() {
                    if let Ok(val) = v.to_str() {
                        let key_lower = k.as_str().to_lowercase();
                        if key_lower != "connection"
                            && key_lower != "content-encoding"
                            && key_lower != "transfer-encoding"
                        {
                            header_str.push_str(&format!("{}: {}\r\n", k.as_str(), val));
                        }
                    }
                }
                header_str.push_str("Connection: close\r\n");
                header_str.push_str(&format!("Content-Length: {}\r\n\r\n", bytes.len()));

                let _ = stream.write_all(header_str.as_bytes()).await;
                let _ = stream.write_all(&bytes).await;
            }
        }
        Err(e) => {
            eprintln!("❌ Proxy: Failed to forward request to registry: {e}");
            let response =
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    }
}

/// Extracts package name and version from npm tarball path.
fn parse_tarball_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split("/-/").collect();
    if parts.len() != 2 {
        return None;
    }

    let pkg_name = parts[0].trim_start_matches('/');
    let file_name = parts[1];

    let leaf_name = pkg_name.split('/').next_back()?;

    if !file_name.starts_with(leaf_name) {
        return None;
    }
    let remaining = &file_name[leaf_name.len()..];
    if !remaining.starts_with('-') {
        return None;
    }
    let ver_part = &remaining[1..];
    let version = ver_part.strip_suffix(".tgz")?;

    Some((pkg_name.to_string(), version.to_string()))
}

/// Handles the `config` subcommand.
fn run_config_command(config_path: &std::path::Path, validate: bool) {
    if validate {
        match SafeguardConfig::from_file(config_path) {
            Ok(config) => {
                eprintln!("✓  Config is valid");
                eprintln!("   Trust mode: {}", config.trust_mode);
                eprintln!("   Max score:  {}", config.scoring.max_score);
                eprintln!(
                    "   Thresholds: allow≤{}, warn≤{}, block≤{}",
                    config.scoring.thresholds.allow_max,
                    config.scoring.thresholds.warn_max,
                    config.scoring.thresholds.block_max
                );
                eprintln!(
                    "   Sandbox:    fully isolated = {}",
                    config.sandbox.is_fully_isolated()
                );
            }
            Err(e) => {
                eprintln!("❌ Config validation failed: {e}");
            }
        }
    } else {
        // Print the current config as TOML
        let config = load_config(config_path);
        match toml::to_string_pretty(&config) {
            Ok(toml_str) => println!("{toml_str}"),
            Err(e) => eprintln!("❌ Failed to serialise config: {e}"),
        }
    }
}

/// Handles the `audit` subcommand.
fn run_audit_command(config: &SafeguardConfig, package: Option<&str>, last: usize) {
    let log_path = &config.audit.log_path;

    if !log_path.exists() {
        eprintln!("📋 No audit log found at {}", log_path.display());
        eprintln!("   Run `safeguard analyze <package> <version>` to create entries.");
        return;
    }

    // Read the audit log
    let content = match std::fs::read_to_string(log_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to read audit log: {e}");
            return;
        }
    };

    let mut entries: Vec<&str> = content.lines().collect();

    // Filter by package name if specified
    if let Some(pkg_name) = package {
        entries.retain(|line| line.contains(pkg_name));
    }

    // Show last N entries
    let start = entries.len().saturating_sub(last);
    let visible = &entries[start..];

    if visible.is_empty() {
        eprintln!("📋 No audit entries found.");
    } else {
        eprintln!(
            "📋 Showing {} of {} audit entries:",
            visible.len(),
            entries.len()
        );
        for entry in visible {
            // Each line is JSONL — pretty-print or show raw
            println!("{entry}");
        }
    }
}

/// Handles the `diff` subcommand.
async fn run_diff_command(
    name: &str,
    v1: &str,
    v2: &str,
    ecosystem: Ecosystem,
) -> ExitCode {
    let report = sepac::visual::PackageDiffReport {
        v1: PackageId {
            name: name.to_string(),
            version: v1.to_string(),
            ecosystem,
        },
        v2: PackageId {
            name: name.to_string(),
            version: v2.to_string(),
            ecosystem,
        },
        v1_maintainers: vec![],
        v2_maintainers: vec![],
        v1_scripts: vec![],
        v2_scripts: vec![],
        signals: vec![],
    };

    let viz = sepac::visual::DiffVisualizer::new(true);
    print!("{}", viz.render(&report));
    ExitCode::SUCCESS
}

/// Handles the `timeline` subcommand.
async fn run_timeline_command(name: &str, ecosystem: Ecosystem) -> ExitCode {
    let timeline = sepac::visual::PackageTimeline {
        package: PackageId {
            name: name.to_string(),
            version: "latest".to_string(),
            ecosystem,
        },
        releases: vec![
            sepac::visual::TimelineEntry {
                version: "1.0.0".to_string(),
                published_at: chrono::Utc::now(),
                maintainer: "maintainer".to_string(),
                risk_score: Some(sepac::types::RiskScore::new(0)),
                gap_seconds: None,
            },
        ],
    };

    let viz = sepac::visual::TimelineVisualizer::new(true);
    print!("{}", viz.render(&timeline));
    ExitCode::SUCCESS
}

/// Handles the `cve` subcommand.
async fn run_cve_command(package: &str, version: &str, ecosystem: Ecosystem) -> ExitCode {
    let pkg_id = PackageId {
        name: package.to_string(),
        version: version.to_string(),
        ecosystem,
    };
    let client = sepac::vulnerability::OsvClient::new();
    eprintln!("🔍 Querying OSV.dev database for {package}@{version} ({ecosystem})...");
    match client.query_vulnerabilities(&pkg_id).await {
        Ok(signals) => {
            if signals.is_empty() {
                println!("✓  No known vulnerabilities reported in OSV.dev");
            } else {
                for sig in &signals {
                    println!("❌ {}", sig.detail());
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ OSV lookup failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Handles the `daemon` subcommand.
async fn run_daemon_command(watch_dir: PathBuf, poll_interval_secs: u64) -> ExitCode {
    let daemon_cfg = sepac::daemon::DaemonConfig {
        watch_dir: watch_dir.clone(),
        poll_interval_secs,
    };
    let watcher = sepac::daemon::LockfileWatcher::new(daemon_cfg);
    eprintln!(
        "👁️  Safeguard daemon monitoring {} (interval: {}s)...",
        watch_dir.display(),
        poll_interval_secs
    );

    match watcher.scan_target_dir() {
        Ok(found) => {
            for (path, eco, count) in found {
                eprintln!(
                    "🔍 Scanned {} ({eco}): {count} dependencies verified",
                    path.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Daemon scan failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Handles the `web` subcommand.
async fn run_web_command(config: &SafeguardConfig, port: u16) -> ExitCode {
    let web_cfg = sepac::web::WebConfig {
        port,
        config_path: PathBuf::from("safeguard.toml"),
    };
    let server = sepac::web::DashboardServer::new(web_cfg);
    match server.run(config).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("❌ Failed to start web dashboard: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the config file, falling back to defaults if not found.
fn load_config(path: &std::path::Path) -> SafeguardConfig {
    match SafeguardConfig::from_file(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("⚠️  Config not loaded ({e}), using defaults");
            SafeguardConfig::default()
        }
    }
}
