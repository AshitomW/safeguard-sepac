# 🛡️ Safeguard (`sepac`)

> [!WARNING]
> **EXPERIMENTAL**
>
> Safeguard (`sepac`) is currently an experiment. Use with caution in real environments.

Safeguard (`sepac`) is a **security utility** designed to protect developers, build servers, and CI/CD pipelines from malicious package dependencies. It intercepts, analyses, and gates package installations based on static analysis, sandboxed execution, and risk scoring.

---

## Features

- **Multi-Phase Risk Analysis**: Combines static code analysis, metadata checks, and sandboxed dynamic execution to identify indicators of compromise (IoCs).
- **Hardened Sandboxed Installation**: Runs install scripts in an isolated, restricted Linux sandbox using user, network, and mount namespaces alongside custom `seccomp` filters.
- **Configurable Risk Scoring**: Weighted additive model mapping risk signals to allow, warn, block, or critical decisions.
- **Append-Only Signed Audit Trail**: Emits replayable JSONL audit events signed via HMAC-SHA256 to prevent tampering.
- **Native Manifest Scanning**: Validates complete dependency trees using `package.json` or `package-lock.json`.
- **Lightweight Registry HTTP Proxy**: Automatically intercepts and evaluates incoming package tarballs, responding with `403 Forbidden` if security gates fail.

---

## 🛠️ CLI Subcommands

Safeguard provides a single unified CLI binary (`sepac`) with subcommands for scanning, analyzing, configuring, proxying, and auditing:

### 1. `sepac analyze <package> <version>`

Evaluates a specific package from the registry and reports a security decision.

```bash
sepac analyze lodash 4.17.21 --ecosystem npm
```

_Options:_

- `-e, --ecosystem`: Target ecosystem (currently `npm`).
- `--force <reason>`: Force override a block decision with a justification (logged in the audit trail).

### 2. `sepac scan <path>`

Parses a package manifest or lockfile, evaluates all resolved dependencies, and exits with a non-zero code if policy blocks any package.

```bash
sepac scan package-lock.json -e npm
```

### 3. `sepac proxy`

Spawns a local HTTP registry proxy server to automatically intercept, evaluate, and stream or block package downloads.

```bash
sepac proxy --port 8080 --ecosystem npm
```

You can point your package manager registry to the proxy:

```bash
npm config set registry http://localhost:8080
```

### 4. `sepac config`

Views or validates the TOML config file.

```bash
sepac config --validate
```

### 5. `sepac audit`

Displays the local HMAC-signed audit log.

```bash
sepac audit --package lodash --last 5
```

---

## ⚙️ Configuration (`safeguard.toml`)

All thresholds, weights, sandbox configurations, and policies are loaded from a data file. Example:

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

[scoring.thresholds]
allow_max = 4
warn_max = 9
block_max = 14

[sandbox]
network_namespace = true
mount_namespace = true
seccomp_enabled = true
syscall_allowlist_path = "/etc/safeguard/syscall_allowlist.toml"
timeout_secs = 30
memory_limit_bytes = 268435456  # 256 MiB

[audit]
log_path = "/var/log/safeguard/audit.jsonl"
hmac_key_path = "/etc/safeguard/hmac.key"
```

---

## Quick Start & Integration

### Wrapper Script

Integrate Safeguard directly with standard `npm install` runs by using the wrapper script:

```bash
chmod +x safeguard-npm-install.sh
./safeguard-npm-install.sh install
```

### Development & Testing

Build and run the project locally using Rust:

```bash
# Check formatting
cargo fmt --all -- --check

# Check for warnings
cargo clippy --all-targets -- -D warnings

# Execute test suite
cargo test
```

### Dockerized Staging

Compile and run Safeguard in a container:

```bash
docker build -t safeguard:latest .
docker run --rm -it safeguard:latest
```

---

## Extending Safeguard (Adding New Ecosystems)

Safeguard is built on top of decoupled boundaries defined by traits. To add a new package ecosystem (e.g., Python/PyPI, Cargo, RubyGems):

### 1. Implement the `PackageSource` Trait

Create a new module in `src/registry/` (e.g. `src/registry/pypi.rs`) and implement the [`PackageSource`](file:///Users/ashi/Desktop/sepac/src/traits/package_source.rs) trait:

- `fetch`: Download and extract tarballs/packages.
- `history`: Query version history metadata.
- `checksum`: Query expected checksums.
- `provenance`: Retrieve build-provenance attestations (if supported).

Register your adapter in [`RegistryAdapterFactory::for_ecosystem`](file:///Users/ashi/Desktop/sepac/src/registry/mod.rs#L25):

```rust
Ecosystem::PyPi => Box::new(pypi::PyPiRegistryAdapter::new()),
```

### 2. Implement Manifest and Lockfile Parsing

In [`src/manifest/mod.rs`](file:///Users/ashi/Desktop/sepac/src/manifest/mod.rs), add a parsing function for the ecosystem's files (e.g., `requirements.txt`, `poetry.lock`, or `Cargo.lock`):

- Parse the file content.
- Map the list of dependencies into a uniform `Vec<PackageId>`.
- Hook it into `parse_manifest`:

```rust
Ecosystem::Cargo => parse_cargo_manifest(path),
```

### 3. Add Custom Risk Signals

If the new ecosystem introduces specific threat indicators:

1. Declare the new variant in the `Signal` enum in [`src/types.rs`](file:///Users/ashi/Desktop/sepac/src/types.rs).
2. Document and assign a weight for it in [`safeguard.toml`](file:///Users/ashi/Desktop/sepac/safeguard.toml) under `[scoring.weights]`.
3. Add the detection logic inside your custom implementation of [`Analyser`](file:///Users/ashi/Desktop/sepac/src/traits/analyser.rs).
