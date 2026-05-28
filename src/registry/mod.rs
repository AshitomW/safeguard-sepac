//! Registry adapters — ecosystem-specific package source implementations.
//!
//! Each ecosystem has one adapter implementing [`PackageSource`]. The
//! [`RegistryAdapterFactory`] creates the right adapter for a given ecosystem.
//! Adding a new ecosystem = adding a new module + one match arm in the factory.

pub mod npm;

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
            // Future ecosystems are added here as new match arms.
            // Each requires only a new module + this one line.
            _ => unimplemented!(
                "registry adapter for {ecosystem} is not yet implemented — \
                 gate behind #[cfg(feature = \"{ecosystem}\")] when ready"
            ),
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
    fn factory_creates_npm_adapter() {
        let _adapter = RegistryAdapterFactory::for_ecosystem(Ecosystem::Npm);
        // If this compiles and doesn't panic, the factory works.
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn factory_panics_for_unimplemented_ecosystem() {
        let _adapter = RegistryAdapterFactory::for_ecosystem(Ecosystem::PyPi);
    }
}
