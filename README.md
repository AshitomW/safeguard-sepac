# Safeguard (`sepac`)

Safeguard (`sepac`) is a package-manager-agnostic security system built in Rust. It protects software projects, build servers, and CI/CD pipelines against modern supply-chain attacks including typosquatting, dependency confusion, exposed secrets, import-time code execution, CI evasion, node-gyp script injection, and known CVE vulnerabilities.

---

## Core Capabilities

### Visual Inspection & Reporting
- **Dependency Tree Heatmap (`sepac tree`)**: Terminal box-drawing dependency tree renderer with risk heatmap coloring.
- **Package Version Diff Viewer (`sepac diff`)**: Side-by-side manifest, script, maintainer, and signal comparison across versions.
- **SBOM Generation (`sepac sbom`)**: Exports SPDX 2.3 JSON and CycloneDX 1.5 JSON compliance manifests.
- **HTML Security Reports (`sepac analyze --format html`)**: Standalone dark-mode HTML security reports.
- **Risk & Release Timeline (`sepac timeline`)**: Version release velocity and historical risk score graphs.

### Threat Detection Analysers
- **Typosquatting Detection (`TyposquatAnalyser`)**: Levenshtein edit distance and homoglyph analysis against popular registry packages.
- **Dependency Confusion (`DependencyConfusionAnalyser`)**: Version inflation (>100.0.0) and internal scope collision detection.
- **Secret Scanning (`SecretScanningAnalyser`)**: Scans for AWS keys, GitHub tokens, NPM tokens, Slack webhooks, and private keys.
- **Import-Time Payload Detection (`ImportTimePayloadAnalyser`)**: Identifies top-level code execution triggered upon module load.
- **CI Attack Flag Evasion (`CIEnvironmentAnalyser`)**: Detects environment overrides (`CI=false`, `RECON_ONLY`, `NO_TELEMETRY`).
- **Phantom GYP Injection (`PhantomGypAnalyser`)**: Flags shell injection in `binding.gyp` and `wscript`.
- **YARA Pattern Matching (`YaraAnalyser`)**: Integrates YARA threat rules against package sources.
- **Vulnerability Query (`sepac cve`)**: Queries OSV.dev for known CVE vulnerabilities with local caching.

### Ecosystem Support
- **NPM**: Complete JavaScript package, manifest, and script analysis.
- **PyPI (`PyPiRegistryAdapter`)**: Python package fetching, metadata, and version history.
- **Cargo (`CargoRegistryAdapter`)**: Rust crates.io crate fetching, checksum verification, and history.
- **RubyGems (`RubyGemsRegistryAdapter`)**: RubyGems.org gem fetching and author verification.

### Platform & Integration
- **Continuous Lockfile Watcher (`sepac daemon`)**: Background service monitoring `package-lock.json`, `Cargo.lock`, `requirements.txt`, and `Gemfile.lock`.
- **Local Web Dashboard (`sepac web`)**: Embedded local HTTP server providing interactive risk metrics and status.
- **Alert Dispatcher**: Real-time Slack webhook and generic HTTP POST notifications for blocked decisions.
- **Policy-as-Code Engine (`PolicyEngine`)**: Evaluates enterprise declarative rules against packages.

### Hardened Sandbox Isolation
- **Linux Namespace Sandbox (`LinuxSandboxExecutor`)**: Hardened isolation using User, PID, Network (`CLONE_NEWNET`), and Mount (`CLONE_NEWNS`) namespaces alongside `seccomp-bpf` allowlists.
- **eBPF Syscall Tracer (`EbpfTracer`)**: Captures raw kernel syscall tracepoints during sandboxed script execution.
- **SQLite Historical Baseline Repository (`SqliteBaselineStore`)**: Tracks package syscall baselines across runs.
- **Sigstore Verification (`SigstoreVerifier`)**: Verifies Rekor transparency logs and Fulcio certificate chains.

---

## CLI Reference & Examples

### Evaluate Package Risk
```bash
# Evaluate NPM package
sepac analyze lodash 4.17.21 --ecosystem npm

# Generate HTML report
sepac analyze requests 2.31.0 -e pypi --format html > report.html
```

### Dependency Tree Heatmap
```bash
sepac tree package-lock.json -e npm
```

### Version Diff Comparison
```bash
sepac diff lodash 4.17.20 4.17.21 -e npm
```

### SBOM Generation (SPDX / CycloneDX)
```bash
# Generate SPDX 2.3 JSON SBOM
sepac sbom package-lock.json --format spdx

# Generate CycloneDX 1.5 JSON SBOM
sepac sbom requirements.txt -e pypi --format cyclonedx
```

### OSV.dev Vulnerability Lookup
```bash
sepac cve express 4.18.2 -e npm
```

### Continuous Daemon Watcher
```bash
sepac daemon --dir . --interval 5
```

### Web Dashboard Server
```bash
sepac web --port 8080
```

### Lockfile Security Scan
```bash
sepac scan Cargo.lock -e cargo
```

### Registry Proxy Interceptor
```bash
sepac proxy --port 8080 --ecosystem npm
```

---

## Configuration (`safeguard.toml`)

```toml
trust_mode = "Balanced"

[scoring]
max_score = 20

[scoring.weights]
runtime-syscall = 4.0
post-install-added = 5.0
new-maintainer = 3.0
binary-blob = 3.0
obfuscated-code = 4.0
typosquat = 4.0
dependency-confusion = 5.0
secret-exposed = 5.0
import-time-exec = 4.0
ci-attack = 4.0
phantom-gyp = 5.0
yara-rule-match = 5.0
known-vulnerability = 4.0

[scoring.thresholds]
allow_max = 4
warn_max = 9
block_max = 14

[sandbox]
network_namespace = true
mount_namespace = true
user_namespace = true
seccomp_enabled = true
syscall_allowlist_path = "/etc/safeguard/syscall_allowlist.toml"
timeout_secs = 30
memory_limit_bytes = 268435456  # 256 MiB

[audit]
log_path = "audit.jsonl"
hmac_key_path = "hmac.key"
```

---

## Building & Testing

```bash
# Execute unit and integration tests
cargo test

# Check formatting
cargo fmt --all -- --check

# Check clippy lints
cargo clippy --all-targets -- -D warnings
```

---

## CI/CD Integration (GitHub Actions)

Include `.github/workflows/safeguard-action.yml` in your repository:

```yaml
name:  Risk Scan
on:
  pull_request:
    paths:
      - '**/package-lock.json'
      - '**/Cargo.lock'
      - '**/requirements.txt'

jobs:
  safeguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: ./target/release/sepac scan package-lock.json -e npm
```

---

## Extending Safeguard

### Adding a New Analyser
Implement the `Analyser` trait in `src/analysis/`:

```rust
impl Analyser for CustomScanner {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        // Inspection logic
        Ok(vec![])
    }
}
```

Register your scanner in `AnalysisPipeline::default_pipeline()` in `src/analysis/pipeline.rs`.

### Adding a New Ecosystem
Implement the `PackageSource` trait in `src/registry/` and register the module in `RegistryAdapterFactory::for_ecosystem` in `src/registry/mod.rs`.
