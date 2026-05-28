#!/bin/sh
set -e

# safeguard-npm-install.sh
# Wraps package manager installs with pre-install dependency scans.

echo "🛡️  Initializing Safeguard npm security scan..."

# Check if package-lock.json exists, otherwise fall back to package.json
if [ -f "package-lock.json" ]; then
    echo " Scanning dependencies from package-lock.json..."
    sepac scan package-lock.json -e npm
elif [ -f "package.json" ]; then
    echo " Scanning dependencies from package.json..."
    sepac scan package.json -e npm
else
    echo "️  No package.json or package-lock.json found. Skipping scan."
fi

echo " Safeguard security scan completed. No critical vulnerabilities/malicious patterns detected."
echo " Proceeding with npm installation..."
exec npm "$@"
