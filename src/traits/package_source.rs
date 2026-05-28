//! The `PackageSource` trait — fetches packages and metadata from a registry.
//!
//! Each ecosystem (npm, PyPI, Cargo, RubyGems) provides one implementation.
//! All other Safeguard layers depend only on this trait, never on a concrete
//! registry client.

use async_trait::async_trait;

use crate::types::{
    Checksum, Ecosystem, PackageArchive, PackageId, Provenance, Result, VersionMeta,
};

/// Fetches packages, version history, checksums, and provenance from a registry.
///
/// # Responsibilities
/// - Downloading package tarballs
/// - Retrieving version history for trend analysis
/// - Verifying integrity via checksums
/// - Querying provenance attestations
///
/// # Implementors
/// One impl per ecosystem. Registered via `RegistryAdapterFactory`.
#[async_trait]
pub trait PackageSource: Send + Sync {
    /// Downloads and extracts the package archive for the given ID.
    async fn fetch(&self, id: &PackageId) -> Result<PackageArchive>;

    /// Returns the full version history for a package name in an ecosystem.
    async fn history(&self, name: &str, ecosystem: Ecosystem) -> Result<Vec<VersionMeta>>;

    /// Returns the registry-provided checksum for a specific package version.
    async fn checksum(&self, id: &PackageId) -> Result<Checksum>;

    /// Returns provenance attestation data, if available.
    ///
    /// Returns `Ok(None)` if the registry does not support provenance
    /// or the package has no attestation — this is not an error.
    async fn provenance(&self, id: &PackageId) -> Result<Option<Provenance>>;
}
