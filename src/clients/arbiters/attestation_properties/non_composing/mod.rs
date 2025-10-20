//! Non-composing attestation property arbiters
//!
//! This module contains arbiters that validate specific properties of attestations
//! in a non-composing manner.

pub mod attester_arbiter_non_composing;
pub mod expiration_time_after_arbiter_non_composing;
pub mod expiration_time_before_arbiter_non_composing;
pub mod expiration_time_equal_arbiter_non_composing;
pub mod recipient_arbiter_non_composing;
pub mod ref_uid_arbiter_non_composing;
pub mod revocable_arbiter_non_composing;
pub mod schema_arbiter_non_composing;
pub mod time_after_arbiter_non_composing;
pub mod time_before_arbiter_non_composing;
pub mod time_equal_arbiter_non_composing;
pub mod uid_arbiter_non_composing;

// Re-export all non-composing arbiters
pub use attester_arbiter_non_composing::*;
pub use expiration_time_after_arbiter_non_composing::*;
pub use expiration_time_before_arbiter_non_composing::*;
pub use expiration_time_equal_arbiter_non_composing::*;
pub use recipient_arbiter_non_composing::*;
pub use ref_uid_arbiter_non_composing::*;
pub use revocable_arbiter_non_composing::*;
pub use schema_arbiter_non_composing::*;
pub use time_after_arbiter_non_composing::*;
pub use time_before_arbiter_non_composing::*;
pub use time_equal_arbiter_non_composing::*;
pub use uid_arbiter_non_composing::*;

#[derive(Clone)]
pub struct AttestationPropertiesNonComposingApi;

impl AttestationPropertiesNonComposingApi {
    pub fn recipient(&self) -> RecipientArbiterNonComposingApi {
        RecipientArbiterNonComposingApi
    }
    pub fn uid(&self) -> UidArbiterNonComposingApi {
        UidArbiterNonComposingApi
    }
    pub fn attester(&self) -> AttesterArbiterNonComposingApi {
        AttesterArbiterNonComposingApi
    }
    pub fn schema(&self) -> SchemaArbiterNonComposingApi {
        SchemaArbiterNonComposingApi
    }
    pub fn revocable(&self) -> RevocableArbiterNonComposingApi {
        RevocableArbiterNonComposingApi
    }
    pub fn expiration_time_after(&self) -> ExpirationTimeAfterArbiterNonComposingApi {
        ExpirationTimeAfterArbiterNonComposingApi
    }
    pub fn expiration_time_before(&self) -> ExpirationTimeBeforeArbiterNonComposingApi {
        ExpirationTimeBeforeArbiterNonComposingApi
    }
    pub fn expiration_time_equal(&self) -> ExpirationTimeEqualArbiterNonComposingApi {
        ExpirationTimeEqualArbiterNonComposingApi
    }
    pub fn ref_uid(&self) -> RefUidArbiterNonComposingApi {
        RefUidArbiterNonComposingApi
    }
    pub fn time_after(&self) -> TimeAfterArbiterNonComposingApi {
        TimeAfterArbiterNonComposingApi
    }
    pub fn time_before(&self) -> TimeBeforeArbiterNonComposingApi {
        TimeBeforeArbiterNonComposingApi
    }
    pub fn time_equal(&self) -> TimeEqualArbiterNonComposingApi {
        TimeEqualArbiterNonComposingApi
    }
}
