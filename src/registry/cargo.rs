//! Cargo / crates.io registry adapter — implements [`PackageSource`] for Rust crates.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::error::{RegistryError, SafeguardError};
use crate::traits::PackageSource;
use crate::types::{
    Checksum, Ecosystem, PackageArchive, PackageId, PackageManifest, Provenance, Result,
    VersionMeta,
};

const CARGO_REGISTRY_URL: &str = "https://crates.io/api/v1";

#[derive(Debug, Deserialize)]
struct CargoCrate {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CargoVersion {
    num: String,
    checksum: Option<String>,
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoCrateResponse {
    #[serde(rename = "crate")]
    crate_info: CargoCrate,
    versions: Option<Vec<CargoVersion>>,
}

/// Cargo / crates.io registry adapter.
pub struct CargoRegistryAdapter {
    client: Client,
    api_url: String,
}

impl Default for CargoRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoRegistryAdapter {
    /// Creates a new `CargoRegistryAdapter`.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("Safeguard-sepac/0.1.0 (security-audit)")
                .build()
                .unwrap_or_default(),
            api_url: CARGO_REGISTRY_URL.to_string(),
        }
    }

    /// Creates an adapter with custom API URL.
    pub fn with_api_url(url: String) -> Self {
        Self {
            client: Client::builder()
                .user_agent("Safeguard-sepac/0.1.0 (security-audit)")
                .build()
                .unwrap_or_default(),
            api_url: url,
        }
    }

    async fn fetch_crate(&self, name: &str) -> Result<CargoCrateResponse> {
        let url = format!("{}/crates/{}", self.api_url, name);
        let resp = self.client.get(&url).send().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::Network {
                url: url.clone(),
                message: e.to_string(),
            })
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(SafeguardError::Registry(RegistryError::NotFound {
                name: name.to_string(),
                version: "*".to_string(),
                ecosystem: "cargo".to_string(),
            }));
        }

        resp.json::<CargoCrateResponse>().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::ParseError {
                url,
                message: format!("invalid crates.io response JSON: {e}"),
            })
        })
    }
}

#[async_trait]
impl PackageSource for CargoRegistryAdapter {
    async fn fetch(&self, id: &PackageId) -> Result<PackageArchive> {
        let res = self.fetch_crate(&id.name).await?;
        let dir = tempfile::tempdir().map_err(SafeguardError::Io)?;
        let extracted_path = dir.path().to_path_buf();

        let manifest = PackageManifest {
            name: res.crate_info.name,
            version: id.version.clone(),
            dependencies: std::collections::HashMap::new(),
            install_scripts: Vec::new(),
            maintainers: vec![],
            has_native_code: true,
        };

        Ok(PackageArchive {
            id: id.clone(),
            extracted_path,
            manifest,
            tarball: vec![],
        })
    }

    async fn history(&self, name: &str, _ecosystem: Ecosystem) -> Result<Vec<VersionMeta>> {
        let res = self.fetch_crate(name).await?;
        let mut history = Vec::new();

        if let Some(versions) = res.versions {
            for v in versions {
                let published_at = v
                    .created_at
                    .as_deref()
                    .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));

                history.push(VersionMeta {
                    version: v.num,
                    published_at,
                    published_by: None,
                    yanked: false,
                });
            }
        }

        Ok(history)
    }

    async fn checksum(&self, id: &PackageId) -> Result<Checksum> {
        let res = self.fetch_crate(&id.name).await?;
        if let Some(versions) = res.versions {
            if let Some(v) = versions.iter().find(|ver| ver.num == id.version) {
                if let Some(sha) = &v.checksum {
                    return Ok(Checksum {
                        algorithm: "sha256".into(),
                        hex_digest: sha.clone(),
                    });
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
    fn default_cargo_adapter() {
        let adapter = CargoRegistryAdapter::new();
        assert_eq!(adapter.api_url, CARGO_REGISTRY_URL);
    }
}
