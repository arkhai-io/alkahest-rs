//! Attestation properties arbiters module
//!
//! This module contains arbiters that validate specific properties of attestations,
//! such as time constraints, recipients, schemas, and other metadata.

pub mod composing;
pub mod non_composing;

// Re-export modules for convenience
pub use composing::*;
pub use non_composing::*;

// Attestation properties group
#[derive(Clone)]
pub struct AttestationPropertiesApi;

impl AttestationPropertiesApi {
    pub fn composing(&self) -> AttestationPropertiesComposingApi {
        AttestationPropertiesComposingApi
    }
    pub fn non_composing(&self) -> AttestationPropertiesNonComposingApi {
        AttestationPropertiesNonComposingApi
    }
}
