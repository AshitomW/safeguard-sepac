//! Software Bill of Materials (SBOM) generator supporting SPDX 2.3 and CycloneDX 1.5 formats.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::manifest::parse_manifest;
use crate::types::{Ecosystem, PackageId, Result};

/// Supported SBOM export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    /// SPDX 2.3 JSON standard.
    Spdx23,
    /// CycloneDX 1.5 JSON standard.
    CycloneDx15,
}

impl std::str::FromStr for SbomFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "spdx" | "spdx-2.3" | "spdx23" => Ok(Self::Spdx23),
            "cyclonedx" | "cyclonedx-1.5" | "cyclonedx15" => Ok(Self::CycloneDx15),
            _ => Err(format!("unsupported SBOM format: '{s}' (use 'spdx' or 'cyclonedx')")),
        }
    }
}

/// Generator for standard compliance SBOM manifests.
#[derive(Debug, Default)]
pub struct SbomGenerator;

impl SbomGenerator {
    /// Creates a new `SbomGenerator`.
    pub fn new() -> Self {
        Self
    }

    /// Generates an SBOM JSON string for a lockfile in the requested format.
    pub fn generate_from_manifest(
        &self,
        path: &Path,
        ecosystem: Ecosystem,
        format: SbomFormat,
    ) -> Result<String> {
        let packages = parse_manifest(path, ecosystem)?;
        let document_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("safeguard-sbom");

        match format {
            SbomFormat::Spdx23 => self.generate_spdx(document_name, ecosystem, &packages),
            SbomFormat::CycloneDx15 => self.generate_cyclonedx(document_name, ecosystem, &packages),
        }
    }

    fn generate_spdx(
        &self,
        doc_name: &str,
        ecosystem: Ecosystem,
        packages: &[PackageId],
    ) -> Result<String> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let spdx_packages: Vec<serde_json::Value> = packages
            .iter()
            .enumerate()
            .map(|(i, pkg)| {
                serde_json::json!({
                    "SPDXID": format!("SPDXRef-Package-{i}"),
                    "name": pkg.name,
                    "versionInfo": pkg.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": format!("pkg:{}/{}@{}", ecosystem, pkg.name, pkg.version)
                        }
                    ]
                })
            })
            .collect();

        let doc = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": format!("https://safeguard.security/sbom/{doc_name}"),
            "creationInfo": {
                "creators": ["Tool: Safeguard-sepac-0.1.0"],
                "created": timestamp
            },
            "packages": spdx_packages
        });

        serde_json::to_string_pretty(&doc).map_err(Into::into)
    }

    fn generate_cyclonedx(
        &self,
        doc_name: &str,
        ecosystem: Ecosystem,
        packages: &[PackageId],
    ) -> Result<String> {
        let components: Vec<serde_json::Value> = packages
            .iter()
            .map(|pkg| {
                serde_json::json!({
                    "type": "library",
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": format!("pkg:{}/{}@{}", ecosystem, pkg.name, pkg.version)
                })
            })
            .collect();

        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": format!("urn:uuid:{}", std::path::Path::new(doc_name).display()),
            "version": 1,
            "metadata": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "tools": [
                    {
                        "vendor": "Safeguard Security",
                        "name": "sepac",
                        "version": "0.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": doc_name
                }
            },
            "components": components
        });

        serde_json::to_string_pretty(&doc).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_from_str_parsing() {
        assert_eq!("spdx".parse::<SbomFormat>().unwrap(), SbomFormat::Spdx23);
        assert_eq!(
            "cyclonedx".parse::<SbomFormat>().unwrap(),
            SbomFormat::CycloneDx15
        );
        assert!("invalid".parse::<SbomFormat>().is_err());
    }

    #[test]
    fn spdx_generation_structure() {
        let sbom_gen = SbomGenerator::new();
        let pkgs = vec![PackageId {
            name: "lodash".into(),
            version: "4.17.21".into(),
            ecosystem: Ecosystem::Npm,
        }];

        let json = sbom_gen.generate_spdx("demo", Ecosystem::Npm, &pkgs).unwrap();
        assert!(json.contains("\"spdxVersion\": \"SPDX-2.3\""));
        assert!(json.contains("\"name\": \"lodash\""));
        assert!(json.contains("pkg:npm/lodash@4.17.21"));
    }
}
