use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts,
    extensions::{AlkahestExtension, ContractModule},
    types::{PublicProvider, WalletProvider},
};
use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider as _,
    rpc::types::{Filter, TransactionReceipt},
    sol_types::SolEvent as _,
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};

pub mod attestation_properties;
pub mod confirmation;
pub mod intrinsics_arbiter2;
pub mod logical;
pub mod specific_attestation_arbiter;
pub mod trusted_oracle_arbiter;
pub mod trusted_party_arbiter;

// Re-export the core arbiters
pub use intrinsics_arbiter2::*;
pub use specific_attestation_arbiter::*;
pub use trusted_oracle_arbiter::*;
pub use trusted_party_arbiter::*;

// Re-export confirmation APIs
pub use confirmation::*;

// Re-export attestation properties APIs
pub use attestation_properties::*;

// Re-export logical APIs
pub use logical::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitersAddresses {
    pub eas: Address,
    pub trusted_party_arbiter: Address,
    pub trivial_arbiter: Address,
    pub specific_attestation_arbiter: Address,
    pub trusted_oracle_arbiter: Address,
    pub intrinsics_arbiter: Address,
    pub intrinsics_arbiter_2: Address,
    pub any_arbiter: Address,
    pub all_arbiter: Address,
    pub uid_arbiter: Address,
    pub recipient_arbiter: Address,
    pub not_arbiter: Address,
    // Composing arbiters
    pub attester_arbiter_composing: Address,
    pub attester_arbiter_non_composing: Address,
    pub expiration_time_after_arbiter_composing: Address,
    pub expiration_time_before_arbiter_composing: Address,
    pub expiration_time_equal_arbiter_composing: Address,
    pub recipient_arbiter_composing: Address,
    pub ref_uid_arbiter_composing: Address,
    pub revocable_arbiter_composing: Address,
    pub schema_arbiter_composing: Address,
    pub time_after_arbiter_composing: Address,
    pub time_before_arbiter_composing: Address,
    pub time_equal_arbiter_composing: Address,
    pub uid_arbiter_composing: Address,
    // Payment fulfillment arbiters
    pub erc20_payment_fulfillment_arbiter: Address,
    pub erc721_payment_fulfillment_arbiter: Address,
    pub erc1155_payment_fulfillment_arbiter: Address,
    pub token_bundle_payment_fulfillment_arbiter: Address,
    // Non-composing arbiters
    pub expiration_time_after_arbiter_non_composing: Address,
    pub expiration_time_before_arbiter_non_composing: Address,
    pub expiration_time_equal_arbiter_non_composing: Address,
    pub recipient_arbiter_non_composing: Address,
    pub ref_uid_arbiter_non_composing: Address,
    pub revocable_arbiter_non_composing: Address,
    pub schema_arbiter_non_composing: Address,
    pub time_after_arbiter_non_composing: Address,
    pub time_before_arbiter_non_composing: Address,
    pub time_equal_arbiter_non_composing: Address,
    pub uid_arbiter_non_composing: Address,
    // Confirmation arbiters
    pub confirmation_arbiter: Address,
    pub confirmation_arbiter_composing: Address,
    pub revocable_confirmation_arbiter: Address,
    pub revocable_confirmation_arbiter_composing: Address,
    pub unrevocable_confirmation_arbiter: Address,
    pub unrevocable_confirmation_arbiter_composing: Address,
}

#[derive(Clone)]
pub struct ArbitersModule {
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: ArbitersAddresses,
}

impl Default for ArbitersAddresses {
    fn default() -> Self {
        BASE_SEPOLIA_ADDRESSES.arbiters_addresses
    }
}

/// Available contracts in the Arbiters module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitersContract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Specific attestation arbiter
    SpecificAttestationArbiter,
    /// Trusted party arbiter
    TrustedPartyArbiter,
    /// Trivial arbiter (always accepts)
    TrivialArbiter,
    /// Trusted oracle arbiter
    TrustedOracleArbiter,
    // Add more as needed - there are many arbiter contracts
}

impl ContractModule for ArbitersModule {
    type Contract = ArbitersContract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            ArbitersContract::Eas => self.addresses.eas,
            ArbitersContract::SpecificAttestationArbiter => {
                self.addresses.specific_attestation_arbiter
            }
            ArbitersContract::TrustedPartyArbiter => self.addresses.trusted_party_arbiter,
            ArbitersContract::TrivialArbiter => self.addresses.trivial_arbiter,
            ArbitersContract::TrustedOracleArbiter => self.addresses.trusted_oracle_arbiter,
        }
    }
}

impl AlkahestExtension for ArbitersModule {
    type Config = ArbitersAddresses;

    async fn init(
        _signer: alloy::signers::local::PrivateKeySigner,
        providers: crate::types::ProviderContext,
        config: Option<Self::Config>,
    ) -> eyre::Result<Self> {
        Self::new(
            (*providers.public).clone(),
            (*providers.wallet).clone(),
            config,
        )
    }
}

#[macro_export]
macro_rules! impl_encode_and_decode {
    ($demand_data_type:ty, $encode_fn:ident, $decode_fn:ident) => {
        impl $crate::clients::arbiters::ArbitersModule {
            pub fn $encode_fn(demand: &$demand_data_type) -> alloy::primitives::Bytes {
                use alloy::sol_types::SolValue as _;
                demand.abi_encode().into()
            }

            pub fn $decode_fn(data: &alloy::primitives::Bytes) -> eyre::Result<$demand_data_type> {
                use alloy::sol_types::SolValue as _;
                Ok(<$demand_data_type>::abi_decode(data)?)
            }
        }
    };
}

impl ArbitersModule {
    pub fn new(
        public_provider: PublicProvider,
        wallet_provider: WalletProvider,
        addresses: Option<ArbitersAddresses>,
    ) -> eyre::Result<Self> {
        Ok(ArbitersModule {
            public_provider,
            wallet_provider,
            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn arbitrate_as_trusted_oracle(
        &self,
        obligation: FixedBytes<32>,
        decision: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            self.addresses.trusted_oracle_arbiter,
            &self.wallet_provider,
        );

        let receipt = trusted_oracle_arbiter
            .arbitrate(obligation, decision)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn wait_for_trusted_oracle_arbitration(
        &self,
        oracle: Address,
        obligation: FixedBytes<32>,
        from_block: Option<u64>,
    ) -> eyre::Result<Log<contracts::TrustedOracleArbiter::ArbitrationMade>> {
        let filter = Filter::new()
            .from_block(from_block.unwrap_or(0))
            .address(self.addresses.trusted_oracle_arbiter)
            .event_signature(contracts::TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH)
            .topic1(obligation)
            .topic2(oracle.into_word());

        let logs = self.public_provider.get_logs(&filter).await?;
        if let Some(log) = logs
            .iter()
            .collect::<Vec<_>>()
            .first()
            .map(|log| log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>())
        {
            return Ok(log?.inner);
        }

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        if let Some(log) = stream.next().await {
            let log = log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>()?;
            return Ok(log.inner);
        }

        Err(eyre::eyre!("No ArbitrationMade event found"))
    }
}

// --- Simple API macros -------------------------------------------------

/// Macro to generate From/TryFrom implementations for DemandData types
#[macro_export]
macro_rules! impl_demand_data_conversions {
    ($demand_type:ty) => {
        impl From<$demand_type> for alloy::primitives::Bytes {
            fn from(demand: $demand_type) -> Self {
                use alloy::sol_types::SolValue as _;
                demand.abi_encode().into()
            }
        }

        impl TryFrom<&alloy::primitives::Bytes> for $demand_type {
            type Error = eyre::Error;

            fn try_from(data: &alloy::primitives::Bytes) -> Result<Self, Self::Error> {
                use alloy::sol_types::SolValue as _;
                Ok(Self::abi_decode(data)?)
            }
        }

        impl TryFrom<alloy::primitives::Bytes> for $demand_type {
            type Error = eyre::Error;

            fn try_from(data: alloy::primitives::Bytes) -> Result<Self, Self::Error> {
                use alloy::sol_types::SolValue as _;
                Ok(Self::abi_decode(&data)?)
            }
        }
    };
}

/// Macro to generate simple API accessors for arbiters
#[macro_export]
macro_rules! impl_arbiter_api {
    ($api_name:ident, $demand_type:ty, $encode_fn:ident, $decode_fn:ident, $contract_field:ident) => {
        #[derive(Clone)]
        pub struct $api_name;

        impl $api_name {
            pub fn encode(&self, demand: &$demand_type) -> alloy::primitives::Bytes {
                ArbitersModule::$encode_fn(demand)
            }

            pub fn decode(&self, data: &alloy::primitives::Bytes) -> eyre::Result<$demand_type> {
                ArbitersModule::$decode_fn(data)
            }

            pub fn address(&self, arbiters: &ArbitersModule) -> alloy::primitives::Address {
                arbiters.addresses.$contract_field
            }
        }
    };
}

impl ArbitersModule {
    /// Access the TrustedOracleArbiter API helper
    pub fn trusted_oracle_arbiter(&self) -> TrustedOracleArbiter {
        TrustedOracleArbiter
    }

    /// Access the SpecificAttestationArbiter API helper  
    pub fn specific_attestation_arbiter(&self) -> SpecificAttestationArbiter {
        SpecificAttestationArbiter
    }

    /// Access the TrustedPartyArbiter API helper
    pub fn trusted_party_arbiter(&self) -> TrustedPartyArbiter {
        TrustedPartyArbiter
    }

    /// Access the IntrinsicsArbiter2 API helper
    pub fn intrinsics_arbiter2(&self) -> IntrinsicsArbiter2 {
        IntrinsicsArbiter2
    }

    /// Access logical arbiters group
    pub fn logical(&self) -> LogicalArbiters {
        LogicalArbiters
    }

    /// Access confirmation arbiters group
    pub fn confirmation(&self) -> ConfirmationArbiters {
        ConfirmationArbiters
    }

    /// Access attestation properties arbiters group
    pub fn attestation_properties(&self) -> AttestationPropertyArbiters {
        AttestationPropertyArbiters
    }
}
