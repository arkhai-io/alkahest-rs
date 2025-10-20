//! Composing attestation property arbiters
//!
//! This module contains arbiters that validate attestation properties
//! in a composable manner, combining base arbiters with property checks.

pub mod attester_arbiter_composing;
pub mod expiration_time_after_arbiter_composing;
pub mod expiration_time_before_arbiter_composing;
pub mod expiration_time_equal_arbiter_composing;
pub mod recipient_arbiter_composing;
pub mod ref_uid_arbiter_composing;
pub mod revocable_arbiter_composing;
pub mod schema_arbiter_composing;
pub mod time_after_arbiter_composing;
pub mod time_before_arbiter_composing;
pub mod time_equal_arbiter_composing;
pub mod uid_arbiter_composing;

// Re-export the contract types and APIs for convenience
pub use attester_arbiter_composing::*;
pub use expiration_time_after_arbiter_composing::*;
pub use expiration_time_before_arbiter_composing::*;
pub use expiration_time_equal_arbiter_composing::*;
pub use recipient_arbiter_composing::*;
pub use ref_uid_arbiter_composing::*;
pub use revocable_arbiter_composing::*;
pub use schema_arbiter_composing::*;
pub use time_after_arbiter_composing::*;
pub use time_before_arbiter_composing::*;
pub use time_equal_arbiter_composing::*;
pub use uid_arbiter_composing::*;

#[derive(Clone)]
pub struct AttestationPropertiesComposingApi;

impl AttestationPropertiesComposingApi {
    pub fn recipient(&self) -> RecipientArbiterComposingApi {
        RecipientArbiterComposingApi
    }
    pub fn uid(&self) -> UidArbiterComposingApi {
        UidArbiterComposingApi
    }
    pub fn attester(&self) -> AttesterArbiterComposingApi {
        AttesterArbiterComposingApi
    }
    pub fn expiration_time_after(&self) -> ExpirationTimeAfterArbiterComposingApi {
        ExpirationTimeAfterArbiterComposingApi
    }
    pub fn expiration_time_before(&self) -> ExpirationTimeBeforeArbiterComposingApi {
        ExpirationTimeBeforeArbiterComposingApi
    }
    pub fn expiration_time_equal(&self) -> ExpirationTimeEqualArbiterComposingApi {
        ExpirationTimeEqualArbiterComposingApi
    }
    pub fn ref_uid(&self) -> RefUidArbiterComposingApi {
        RefUidArbiterComposingApi
    }
    pub fn revocable(&self) -> RevocableArbiterComposingApi {
        RevocableArbiterComposingApi
    }
    pub fn schema(&self) -> SchemaArbiterComposingApi {
        SchemaArbiterComposingApi
    }
    pub fn time_after(&self) -> TimeAfterArbiterComposingApi {
        TimeAfterArbiterComposingApi
    }
    pub fn time_before(&self) -> TimeBeforeArbiterComposingApi {
        TimeBeforeArbiterComposingApi
    }
    pub fn time_equal(&self) -> TimeEqualArbiterComposingApi {
        TimeEqualArbiterComposingApi
    }
}
