# ============================================================================
# Stage 1: Build the Safeguard (sepac) Binary
# ============================================================================
FROM rust:slim AS builder

WORKDIR /usr/src/sepac

# Copy source code and build dependencies
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Compile the production-ready release binary
# (Since reqwest is built with rustls-tls, no OpenSSL dependencies are needed)
RUN cargo build --release

# ============================================================================
# Stage 2: Application Runner / Execution Environment
# ============================================================================
FROM node:20-slim AS runner

# Install general utilities (like curl/ca-certificates for registry fetches)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the built Safeguard binary
COPY --from=builder /usr/src/sepac/target/release/sepac /usr/local/bin/sepac

# Copy default config file
COPY safeguard.toml /etc/safeguard/safeguard.toml

# Create required configuration and log directories
RUN mkdir -p /etc/safeguard /var/log/safeguard && \
    touch /var/log/safeguard/audit.jsonl

# Generate a cryptographically secure 32-byte HMAC key for signed audit logs,
# and write a default syscall allowlist for sandbox rules
RUN node -e " \
    const fs = require('fs'); \
    fs.writeFileSync('/etc/safeguard/hmac.key', require('crypto').randomBytes(32)); \
    fs.writeFileSync('/etc/safeguard/syscall_allowlist.toml', 'allowed = [\"read\", \"write\", \"open\", \"close\", \"execve\", \"connect\"]\n'); \
"

# Copy the npm install security wrapper script
COPY safeguard-npm-install.sh /usr/local/bin/safeguard-npm-install
RUN chmod +x /usr/local/bin/safeguard-npm-install

# Set up working directory for the application
WORKDIR /usr/src/app

# ============================================================================
# Example Usage: Package manager install gate run
# ============================================================================
# We create a dummy package.json to demonstrate Safeguard auditing dependencies
# at build-time.
RUN echo '{\n\
  "name": "example-app",\n\
  "version": "1.0.0",\n\
  "dependencies": {\n\
    "express": "4.19.2"\n\
  }\n\
}' > package.json

# Perform the secure installation. 
# This runs the safeguard check on all dependencies (express and its transitives) 
# and fails the Docker build if any malicious or blocked package is found.
RUN safeguard-npm-install install --no-audit --no-fund

# Print the audit log summary to verify that packages were checked and logged
RUN sepac audit --last 10

# Command to run the application
CMD [ "node" ]
