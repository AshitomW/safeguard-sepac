//! npm registry adapter — implements [`PackageSource`] for the npm ecosystem.
//!
//! Fetches packages and metadata from `registry.npmjs.org`. Parses
//! `package.json` manifests, extracts tarballs, and queries provenance
//! attestations via the npm attestation API.

use std::collections::HashMap;

use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use reqwest::Client;
use serde::Deserialize;
use tar::Archive;

use crate::error::{RegistryError, SafeguardError};
use crate::traits::PackageSource;
use crate::types::{
    Checksum, Ecosystem, InstallScript, PackageArchive, PackageId, PackageManifest, Provenance,
    Result, VersionMeta,
};

/// Base URL for the npm registry API.
const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// npm registry adapter.
///
/// # Design
/// - Translates npm-specific API responses into
///   Safeguard's universal domain types.
/// - **Single responsibility**: Only fetches from npm; never analyses
///   or scores.
/// - **Substitutable**: Implements `PackageSource`, droppable wherever
///   a `Box<dyn PackageSource>` is expected.
pub struct NpmRegistryAdapter {
    client: Client,
    registry_url: String,
}

impl NpmRegistryAdapter {
    /// Creates a new adapter pointing at the public npm registry.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            registry_url: NPM_REGISTRY_URL.to_string(),
        }
    }

    /// Creates an adapter pointing at a custom registry URL (for testing).
    pub fn with_registry_url(url: String) -> Self {
        Self {
            client: Client::new(),
            registry_url: url,
        }
    }

    /// Fetches the full package document from the npm registry.
    async fn fetch_package_document(&self, name: &str) -> Result<NpmPackageDocument> {
        let url = format!("{}/{}", self.registry_url, name);
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                SafeguardError::Registry(RegistryError::Network {
                    url: url.clone(),
                    message: e.to_string(),
                })
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(SafeguardError::Registry(RegistryError::NotFound {
                name: name.to_string(),
                version: "*".to_string(),
                ecosystem: "npm".to_string(),
            }));
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(SafeguardError::Registry(RegistryError::RateLimited {
                registry: "npm".to_string(),
                retry_after_secs: 60,
            }));
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SafeguardError::Registry(RegistryError::HttpError {
                status_code: status.as_u16(),
                url,
                body: body.chars().take(500).collect(),
            }));
        }

        response.json::<NpmPackageDocument>().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::Network {
                url,
                message: format!("failed to parse JSON: {e}"),
            })
        })
    }

    /// Downloads the tarball for a specific version.
    async fn download_tarball(&self, tarball_url: &str) -> Result<Vec<u8>> {
        let response = self.client.get(tarball_url).send().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::Network {
                url: tarball_url.to_string(),
                message: e.to_string(),
            })
        })?;

        if !response.status().is_success() {
            return Err(SafeguardError::Registry(RegistryError::HttpError {
                status_code: response.status().as_u16(),
                url: tarball_url.to_string(),
                body: "tarball download failed".to_string(),
            }));
        }

        response.bytes().await.map(|b| b.to_vec()).map_err(|e| {
            SafeguardError::Registry(RegistryError::Network {
                url: tarball_url.to_string(),
                message: format!("failed to read tarball bytes: {e}"),
            })
        })
    }

    /// Extracts a gzipped tarball to a temporary directory.
    fn extract_tarball(tarball_bytes: &[u8]) -> Result<PathBuf> {
        let temp_dir = tempfile::tempdir().map_err(|e| {
            SafeguardError::Io(std::io::Error::other(format!(
                "failed to create temp dir: {e}"
            )))
        })?;

        let path = temp_dir.path().to_path_buf();
        let gz = GzDecoder::new(tarball_bytes);
        let mut archive = Archive::new(gz);

        archive.unpack(&path).map_err(|e| {
            SafeguardError::Io(std::io::Error::other(format!(
                "failed to extract tarball: {e}"
            )))
        })?;

        // Keep the temp dir from being cleaned up
        let _ = temp_dir.keep();

        Ok(path)
    }

    /// Parses a `PackageManifest` from an npm version document.
    fn parse_manifest(version_doc: &NpmVersionDocument) -> PackageManifest {
        let mut install_scripts = Vec::new();
        if let Some(scripts) = &version_doc.scripts {
            for phase in &["preinstall", "install", "postinstall"] {
                if let Some(cmd) = scripts.get(*phase) {
                    install_scripts.push(InstallScript {
                        phase: (*phase).to_string(),
                        command: cmd.clone(),
                    });
                }
            }
        }

        let dependencies = version_doc.dependencies.clone().unwrap_or_default();

        let maintainers = version_doc
            .maintainers
            .as_ref()
            .map(|ms| ms.iter().map(|m| m.name.clone()).collect())
            .unwrap_or_default();

        let has_native_code = version_doc.scripts.as_ref().is_some_and(|s| {
            s.values()
                .any(|v| v.contains("node-gyp") || v.contains("prebuild") || v.contains("cmake"))
        });

        PackageManifest {
            name: version_doc.name.clone().unwrap_or_default(),
            version: version_doc.version.clone().unwrap_or_default(),
            dependencies,
            install_scripts,
            maintainers,
            has_native_code,
        }
    }
}

impl Default for NpmRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageSource for NpmRegistryAdapter {
    async fn fetch(&self, id: &PackageId) -> Result<PackageArchive> {
        let doc = self.fetch_package_document(&id.name).await?;

        let version_doc = doc.versions.get(&id.version).ok_or_else(|| {
            SafeguardError::Registry(RegistryError::NotFound {
                name: id.name.clone(),
                version: id.version.clone(),
                ecosystem: "npm".to_string(),
            })
        })?;

        let tarball_url = version_doc
            .dist
            .as_ref()
            .and_then(|d| d.tarball.as_ref())
            .ok_or_else(|| {
                SafeguardError::Registry(RegistryError::Network {
                    url: format!("{}/{}", self.registry_url, id.name),
                    message: "no tarball URL in version metadata".to_string(),
                })
            })?;

        let tarball = self.download_tarball(tarball_url).await?;
        let extracted_path = Self::extract_tarball(&tarball)?;
        let manifest = Self::parse_manifest(version_doc);

        Ok(PackageArchive {
            id: id.clone(),
            extracted_path,
            manifest,
            tarball,
        })
    }

    async fn history(&self, name: &str, _ecosystem: Ecosystem) -> Result<Vec<VersionMeta>> {
        let doc = self.fetch_package_document(name).await?;

        let mut versions: Vec<VersionMeta> = doc
            .versions
            .iter()
            .map(|(ver, ver_doc)| {
                let published_at = doc
                    .time
                    .as_ref()
                    .and_then(|t| t.get(ver))
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok());

                let published_by = ver_doc.npm_user.as_ref().map(|u| u.name.clone());

                let yanked = doc
                    .versions
                    .get(ver)
                    .and_then(|v| v.deprecated.as_ref())
                    .is_some();

                VersionMeta {
                    version: ver.clone(),
                    published_at,
                    published_by,
                    yanked,
                }
            })
            .collect();

        // Sort by publish time (oldest first)
        versions.sort_by(|a, b| a.published_at.cmp(&b.published_at));

        Ok(versions)
    }

    async fn checksum(&self, id: &PackageId) -> Result<Checksum> {
        let doc = self.fetch_package_document(&id.name).await?;

        let version_doc = doc.versions.get(&id.version).ok_or_else(|| {
            SafeguardError::Registry(RegistryError::NotFound {
                name: id.name.clone(),
                version: id.version.clone(),
                ecosystem: "npm".to_string(),
            })
        })?;

        let shasum = version_doc
            .dist
            .as_ref()
            .and_then(|d| d.shasum.as_ref())
            .ok_or_else(|| {
                SafeguardError::Registry(RegistryError::Network {
                    url: format!("{}/{}", self.registry_url, id.name),
                    message: "no shasum in dist metadata".to_string(),
                })
            })?;

        Ok(Checksum {
            algorithm: "sha1".to_string(),
            hex_digest: shasum.clone(),
        })
    }

    async fn provenance(&self, id: &PackageId) -> Result<Option<Provenance>> {
        // npm provenance attestations are available at a separate endpoint.
        // For packages with Sigstore provenance, the dist object contains
        // attestations. We check if any exist.
        let doc = self.fetch_package_document(&id.name).await?;

        let version_doc = match doc.versions.get(&id.version) {
            Some(v) => v,
            None => return Ok(None),
        };

        let has_attestation = version_doc
            .dist
            .as_ref()
            .and_then(|d| d.attestations.as_ref())
            .is_some();

        if has_attestation {
            Ok(Some(Provenance {
                sigstore_verified: true,
                build_system: Some("npm provenance".to_string()),
                source_repo: version_doc.repository_url(),
                reproducible: None,
            }))
        } else {
            Ok(Some(Provenance {
                sigstore_verified: false,
                build_system: None,
                source_repo: version_doc.repository_url(),
                reproducible: None,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// npm API response types (private, serde-only)
// ---------------------------------------------------------------------------

/// Top-level npm package document (GET /{package}).
#[derive(Debug, Deserialize)]
struct NpmPackageDocument {
    /// All published versions: version string → version document.
    #[serde(default)]
    versions: HashMap<String, NpmVersionDocument>,

    /// Publish timestamps: version string → ISO 8601 timestamp.
    #[serde(default)]
    time: Option<HashMap<String, String>>,
}

/// A single version within an npm package document.
#[derive(Debug, Deserialize)]
struct NpmVersionDocument {
    /// Package name.
    name: Option<String>,
    /// Version string.
    version: Option<String>,
    /// npm scripts (preinstall, postinstall, etc.).
    scripts: Option<HashMap<String, String>>,
    /// Direct dependencies.
    dependencies: Option<HashMap<String, String>>,
    /// Maintainers list.
    maintainers: Option<Vec<NpmUser>>,
    /// Distribution metadata (tarball URL, checksums).
    dist: Option<NpmDist>,
    /// The user who published this version.
    #[serde(rename = "_npmUser")]
    npm_user: Option<NpmUser>,
    /// Deprecation message (if yanked).
    deprecated: Option<String>,
    /// Repository metadata.
    repository: Option<NpmRepository>,
}

impl NpmVersionDocument {
    /// Extracts the repository URL, if available.
    fn repository_url(&self) -> Option<String> {
        self.repository.as_ref().map(|r| r.url.clone())
    }
}

/// npm user reference.
#[derive(Debug, Deserialize)]
struct NpmUser {
    name: String,
}

/// npm distribution metadata.
#[derive(Debug, Deserialize)]
struct NpmDist {
    /// URL to the tarball.
    tarball: Option<String>,
    /// SHA-1 checksum.
    shasum: Option<String>,
    /// SHA-512 integrity hash (SRI format).
    #[allow(dead_code)]
    integrity: Option<String>,
    /// Provenance attestations (Sigstore).
    attestations: Option<serde_json::Value>,
}

/// npm repository metadata.
#[derive(Debug, Deserialize)]
struct NpmRepository {
    /// Repository URL.
    #[serde(default)]
    url: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_with_scripts() {
        let mut scripts = HashMap::new();
        scripts.insert("postinstall".to_string(), "node setup.js".to_string());
        scripts.insert("test".to_string(), "jest".to_string());

        let doc = NpmVersionDocument {
            name: Some("test-pkg".into()),
            version: Some("1.0.0".into()),
            scripts: Some(scripts),
            dependencies: Some({
                let mut d = HashMap::new();
                d.insert("lodash".into(), "^4.17.0".into());
                d
            }),
            maintainers: Some(vec![NpmUser {
                name: "alice".into(),
            }]),
            dist: None,
            npm_user: None,
            deprecated: None,
            repository: None,
        };

        let manifest = NpmRegistryAdapter::parse_manifest(&doc);
        assert_eq!(manifest.name, "test-pkg");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.install_scripts.len(), 1);
        assert_eq!(manifest.install_scripts[0].phase, "postinstall");
        assert_eq!(manifest.install_scripts[0].command, "node setup.js");
        assert_eq!(manifest.dependencies.len(), 1);
        assert!(manifest.dependencies.contains_key("lodash"));
        assert_eq!(manifest.maintainers, vec!["alice"]);
        assert!(!manifest.has_native_code);
    }

    #[test]
    fn parse_manifest_detects_native_code() {
        let mut scripts = HashMap::new();
        scripts.insert("install".to_string(), "node-gyp rebuild".to_string());

        let doc = NpmVersionDocument {
            name: Some("native-pkg".into()),
            version: Some("2.0.0".into()),
            scripts: Some(scripts),
            dependencies: None,
            maintainers: None,
            dist: None,
            npm_user: None,
            deprecated: None,
            repository: None,
        };

        let manifest = NpmRegistryAdapter::parse_manifest(&doc);
        assert!(manifest.has_native_code);
    }

    #[test]
    fn parse_manifest_empty_scripts() {
        let doc = NpmVersionDocument {
            name: Some("simple-pkg".into()),
            version: Some("0.1.0".into()),
            scripts: None,
            dependencies: None,
            maintainers: None,
            dist: None,
            npm_user: None,
            deprecated: None,
            repository: None,
        };

        let manifest = NpmRegistryAdapter::parse_manifest(&doc);
        assert!(manifest.install_scripts.is_empty());
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.maintainers.is_empty());
    }

    #[test]
    fn adapter_default_trait() {
        let _adapter = NpmRegistryAdapter::default();
    }

    #[test]
    fn repository_url_extraction() {
        let doc = NpmVersionDocument {
            name: None,
            version: None,
            scripts: None,
            dependencies: None,
            maintainers: None,
            dist: None,
            npm_user: None,
            deprecated: None,
            repository: Some(NpmRepository {
                url: "https://github.com/test/repo".into(),
            }),
        };
        assert_eq!(
            doc.repository_url(),
            Some("https://github.com/test/repo".to_string())
        );
    }

    #[test]
    fn repository_url_none_when_missing() {
        let doc = NpmVersionDocument {
            name: None,
            version: None,
            scripts: None,
            dependencies: None,
            maintainers: None,
            dist: None,
            npm_user: None,
            deprecated: None,
            repository: None,
        };
        assert!(doc.repository_url().is_none());
    }
}
