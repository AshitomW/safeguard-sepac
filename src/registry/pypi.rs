//! PyPI registry adapter — implements [`PackageSource`] for Python packages.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::error::{RegistryError, SafeguardError};
use crate::traits::PackageSource;
use crate::types::{
    Checksum, Ecosystem, PackageArchive, PackageId, PackageManifest, Provenance, Result,
    VersionMeta,
};

const PYPI_REGISTRY_URL: &str = "https://pypi.org";

#[derive(Debug, Deserialize)]
struct PyPiInfo {
    name: String,
    version: String,
    author: Option<String>,
    author_email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyPiReleaseFile {
    digests: Option<PyPiDigests>,
}

#[derive(Debug, Deserialize)]
struct PyPiDigests {
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyPiPackageDocument {
    info: PyPiInfo,
    releases: Option<std::collections::HashMap<String, Vec<PyPiReleaseFile>>>,
}

/// PyPI registry adapter.
pub struct PyPiRegistryAdapter {
    client: Client,
    registry_url: String,
}

impl Default for PyPiRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PyPiRegistryAdapter {
    /// Creates a new `PyPiRegistryAdapter`.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            registry_url: PYPI_REGISTRY_URL.to_string(),
        }
    }

    /// Creates an adapter with custom base URL.
    pub fn with_registry_url(url: String) -> Self {
        Self {
            client: Client::new(),
            registry_url: url,
        }
    }

    async fn fetch_doc(&self, name: &str) -> Result<PyPiPackageDocument> {
        let url = format!("{}/pypi/{}/json", self.registry_url, name);
        let resp = self
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

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SafeguardError::Registry(RegistryError::NotFound {
                name: name.to_string(),
                version: "*".to_string(),
                ecosystem: "pypi".to_string(),
            }));
        }

        resp.json::<PyPiPackageDocument>().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::ParseError {
                url,
                message: format!("invalid PyPI response JSON: {e}"),
            })
        })
    }
}

#[async_trait]
impl PackageSource for PyPiRegistryAdapter {
    async fn fetch(&self, id: &PackageId) -> Result<PackageArchive> {
        let doc = self.fetch_doc(&id.name).await?;
        let mut maintainers = Vec::new();
        if let Some(email) = doc.info.author_email {
            maintainers.push(email);
        } else if let Some(author) = doc.info.author {
            maintainers.push(author);
        }

        let dir = tempfile::tempdir().map_err(SafeguardError::Io)?;
        let extracted_path = dir.path().to_path_buf();

        let manifest = PackageManifest {
            name: doc.info.name,
            version: doc.info.version,
            dependencies: std::collections::HashMap::new(),
            install_scripts: Vec::new(),
            maintainers,
            has_native_code: false,
        };

        Ok(PackageArchive {
            id: id.clone(),
            extracted_path,
            manifest,
            tarball: vec![],
        })
    }

    async fn history(&self, name: &str, _ecosystem: Ecosystem) -> Result<Vec<VersionMeta>> {
        let doc = self.fetch_doc(name).await?;
        let mut history = Vec::new();

        if let Some(releases) = doc.releases {
            for (version, _files) in releases {
                history.push(VersionMeta {
                    version,
                    published_at: None,
                    published_by: doc.info.author.clone(),
                    yanked: false,
                });
            }
        }

        Ok(history)
    }

    async fn checksum(&self, id: &PackageId) -> Result<Checksum> {
        let doc = self.fetch_doc(&id.name).await?;
        if let Some(releases) = doc.releases {
            if let Some(files) = releases.get(&id.version) {
                if let Some(f) = files.first() {
                    if let Some(d) = &f.digests {
                        if let Some(sha) = &d.sha256 {
                            return Ok(Checksum {
                                algorithm: "sha256".into(),
                                hex_digest: sha.clone(),
                            });
                        }
                    }
                }
            }
        }
        Ok(Checksum {
            algorithm: "sha256".into(),
            hex_digest: "00000000000000000000000000000000".into(),
        })
    }

    async fn provenance(&self, _id: &PackageId) -> Result<Option<Provenance>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_adapter_creation() {
        let adapter = PyPiRegistryAdapter::new();
        assert_eq!(adapter.registry_url, PYPI_REGISTRY_URL);
    }
}
