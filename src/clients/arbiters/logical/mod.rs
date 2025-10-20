//! Logical arbiters module
//!
//! This module contains logical arbiters that combine multiple arbiters
//! using logical operations (ANY, ALL, NOT).

pub mod all_arbiter;
pub mod any_arbiter;
pub mod not_arbiter;

pub use all_arbiter::{AllArbiter, AllArbiterApi};
pub use any_arbiter::{AnyArbiter, AnyArbiterApi};
pub use not_arbiter::{NotArbiter, NotArbiterApi};

// Logical arbiters group
#[derive(Clone)]
pub struct LogicalArbitersApi;

impl LogicalArbitersApi {
    pub fn any(&self) -> AnyArbiterApi {
        AnyArbiterApi
    }
    pub fn all(&self) -> AllArbiterApi {
        AllArbiterApi
    }
    pub fn not(&self) -> NotArbiterApi {
        NotArbiterApi
    }
}
