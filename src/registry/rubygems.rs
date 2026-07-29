//! RubyGems.org registry adapter — implements [`PackageSource`] for Ruby gems.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::error::{RegistryError, SafeguardError};
use crate::traits::PackageSource;
use crate::types::{
    Checksum, Ecosystem, PackageArchive, PackageId, PackageManifest, Provenance, Result,
    VersionMeta,
};

const RUBYGEMS_REGISTRY_URL: &str = "https://rubygems.org/api/v1";

#[derive(Debug, Deserialize)]
struct RubyGemInfo {
    name: String,
    version: String,
    authors: Option<String>,
    sha: Option<String>,
}

/// RubyGems registry adapter.
pub struct RubyGemsRegistryAdapter {
    client: Client,
    api_url: String,
}

impl Default for RubyGemsRegistryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RubyGemsRegistryAdapter {
    /// Creates a new `RubyGemsRegistryAdapter`.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            api_url: RUBYGEMS_REGISTRY_URL.to_string(),
        }
    }

    /// Creates an adapter with custom API URL.
    pub fn with_api_url(url: String) -> Self {
        Self {
            client: Client::new(),
            api_url: url,
        }
    }

    async fn fetch_gem(&self, name: &str) -> Result<RubyGemInfo> {
        let url = format!("{}/gems/{}.json", self.api_url, name);
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
                ecosystem: "rubygems".to_string(),
            }));
        }

        resp.json::<RubyGemInfo>().await.map_err(|e| {
            SafeguardError::Registry(RegistryError::ParseError {
                url,
                message: format!("invalid RubyGems response JSON: {e}"),
            })
        })
    }
}

#[async_trait]
impl PackageSource for RubyGemsRegistryAdapter {
    async fn fetch(&self, id: &PackageId) -> Result<PackageArchive> {
        let gem = self.fetch_gem(&id.name).await?;
        let dir = tempfile::tempdir().map_err(SafeguardError::Io)?;
        let extracted_path = dir.path().to_path_buf();

        let maintainers = gem
            .authors
            .map(|a| vec![a])
            .unwrap_or_default();

        let manifest = PackageManifest {
            name: gem.name,
            version: gem.version,
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
        let gem = self.fetch_gem(name).await?;
        Ok(vec![VersionMeta {
            version: gem.version,
            published_at: None,
            published_by: gem.authors,
            yanked: false,
        }])
    }

    async fn checksum(&self, id: &PackageId) -> Result<Checksum> {
        let gem = self.fetch_gem(&id.name).await?;
        if let Some(sha) = gem.sha {
            return Ok(Checksum {
                algorithm: "sha256".into(),
                hex_digest: sha,
            });
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
    fn default_rubygems_adapter() {
        let adapter = RubyGemsRegistryAdapter::new();
        assert_eq!(adapter.api_url, RUBYGEMS_REGISTRY_URL);
    }
}
