//! Registry adapters — ecosystem-specific package source implementations.
//!
//! Each ecosystem has one adapter implementing [`PackageSource`]. The
//! [`RegistryAdapterFactory`] creates the right adapter for a given ecosystem.
//! Adding a new ecosystem = adding a new module + one match arm in the factory.

pub mod cargo;
pub mod npm;
pub mod pypi;
pub mod rubygems;

use crate::traits::PackageSource;
use crate::types::Ecosystem;

/// Factory for creating ecosystem-specific registry adapters.
///
/// # Design
/// - Centralised adapter creation.
/// - Adding a new ecosystem means adding a module and
///   one match arm here — no changes to any other layer.
pub struct RegistryAdapterFactory;

impl RegistryAdapterFactory {
    /// Creates a `PackageSource` adapter for the given ecosystem.
    ///
    /// Returns a boxed trait object that can be used by all downstream layers
    /// without knowledge of the concrete adapter type.
    pub fn for_ecosystem(ecosystem: Ecosystem) -> Box<dyn PackageSource> {
        match ecosystem {
            Ecosystem::Npm => Box::new(npm::NpmRegistryAdapter::new()),
            Ecosystem::PyPi => Box::new(pypi::PyPiRegistryAdapter::new()),
            Ecosystem::Cargo => Box::new(cargo::CargoRegistryAdapter::new()),
            Ecosystem::RubyGems => Box::new(rubygems::RubyGemsRegistryAdapter::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_creates_all_adapters() {
        let _npm = RegistryAdapterFactory::for_ecosystem(Ecosystem::Npm);
        let _pypi = RegistryAdapterFactory::for_ecosystem(Ecosystem::PyPi);
        let _cargo = RegistryAdapterFactory::for_ecosystem(Ecosystem::Cargo);
        let _rubygems = RegistryAdapterFactory::for_ecosystem(Ecosystem::RubyGems);
    }
}
