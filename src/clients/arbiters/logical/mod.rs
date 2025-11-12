//! Logical arbiters module
//!
//! This module contains logical arbiters that combine multiple arbiters
//! using logical operations (ANY, ALL, NOT).
//!
//! These arbiters use trait-based encoding/decoding for convenient .into() conversions.

pub mod all_arbiter;
pub mod any_arbiter;
pub mod not_arbiter;

// Re-export key types for easier access
pub use all_arbiter::DecodedAllArbiterDemandData;
pub use any_arbiter::DecodedAnyArbiterDemandData;
pub use not_arbiter::DecodedNotArbiterDemandData;
