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

/// Decoded demand data from AllArbiter sub-demands
#[derive(Debug, Clone)]
pub enum DecodedDemand {
    // Core arbiters (no demand data)
    TrivialArbiter,

    // Core arbiters (with demand data)
    SpecificAttestation(contracts::SpecificAttestationArbiter::DemandData),
    TrustedParty(contracts::TrustedPartyArbiter::DemandData),
    TrustedOracle(contracts::TrustedOracleArbiter::DemandData),
    IntrinsicsArbiter2(contracts::IntrinsicsArbiter2::DemandData),

    // Logical arbiters
    AnyArbiter(contracts::logical::AnyArbiter::DemandData),
    AllArbiter(contracts::logical::AllArbiter::DemandData),
    NotArbiter(contracts::logical::NotArbiter::DemandData),

    // Confirmation arbiters (most don't have demand data)
    ConfirmationArbiter,
    ConfirmationArbiterComposing,
    RevocableConfirmationArbiter,
    RevocableConfirmationArbiterComposing,
    UnrevocableConfirmationArbiter,
    UnrevocableConfirmationArbiterComposing,

    // Payment fulfillment arbiters (no demand data)
    ERC20PaymentFulfillmentArbiter,
    ERC721PaymentFulfillmentArbiter,
    ERC1155PaymentFulfillmentArbiter,
    TokenBundlePaymentFulfillmentArbiter,

    // Attestation property arbiters - composing
    AttesterArbiterComposing(
        contracts::attestation_properties::composing::AttesterArbiter::DemandData,
    ),
    ExpirationTimeAfterArbiterComposing(
        contracts::attestation_properties::composing::ExpirationTimeAfterArbiter::DemandData,
    ),
    ExpirationTimeBeforeArbiterComposing(
        contracts::attestation_properties::composing::ExpirationTimeBeforeArbiter::DemandData,
    ),
    ExpirationTimeEqualArbiterComposing(
        contracts::attestation_properties::composing::ExpirationTimeEqualArbiter::DemandData,
    ),
    RecipientArbiterComposing(
        contracts::attestation_properties::composing::RecipientArbiter::DemandData,
    ),
    RefUidArbiterComposing(contracts::attestation_properties::composing::RefUidArbiter::DemandData),
    RevocableArbiterComposing(
        contracts::attestation_properties::composing::RevocableArbiter::DemandData,
    ),
    SchemaArbiterComposing(contracts::attestation_properties::composing::SchemaArbiter::DemandData),
    TimeAfterArbiterComposing(
        contracts::attestation_properties::composing::TimeAfterArbiter::DemandData,
    ),
    TimeBeforeArbiterComposing(
        contracts::attestation_properties::composing::TimeBeforeArbiter::DemandData,
    ),
    TimeEqualArbiterComposing(
        contracts::attestation_properties::composing::TimeEqualArbiter::DemandData,
    ),
    UidArbiterComposing(contracts::attestation_properties::composing::UidArbiter::DemandData),

    // Attestation property arbiters - non-composing
    AttesterArbiterNonComposing(
        contracts::attestation_properties::non_composing::AttesterArbiter::DemandData,
    ),
    ExpirationTimeAfterArbiterNonComposing(
        contracts::attestation_properties::non_composing::ExpirationTimeAfterArbiter::DemandData,
    ),
    ExpirationTimeBeforeArbiterNonComposing(
        contracts::attestation_properties::non_composing::ExpirationTimeBeforeArbiter::DemandData,
    ),
    ExpirationTimeEqualArbiterNonComposing(
        contracts::attestation_properties::non_composing::ExpirationTimeEqualArbiter::DemandData,
    ),
    RecipientArbiterNonComposing(
        contracts::attestation_properties::non_composing::RecipientArbiter::DemandData,
    ),
    RefUidArbiterNonComposing(
        contracts::attestation_properties::non_composing::RefUidArbiter::DemandData,
    ),
    RevocableArbiterNonComposing(
        contracts::attestation_properties::non_composing::RevocableArbiter::DemandData,
    ),
    SchemaArbiterNonComposing(
        contracts::attestation_properties::non_composing::SchemaArbiter::DemandData,
    ),
    TimeAfterArbiterNonComposing(
        contracts::attestation_properties::non_composing::TimeAfterArbiter::DemandData,
    ),
    TimeBeforeArbiterNonComposing(
        contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData,
    ),
    TimeEqualArbiterNonComposing(
        contracts::attestation_properties::non_composing::TimeEqualArbiter::DemandData,
    ),
    UidArbiterNonComposing(
        contracts::attestation_properties::non_composing::UidArbiter::DemandData,
    ),
    // Unknown arbiter
    Unknown {
        arbiter: Address,
        raw_data: alloy::primitives::Bytes,
    },
}

impl ArbitersModule {
    /// Generic function to decode a single arbiter demand based on its address
    pub fn decode_arbiter_demand(
        &self,
        arbiter_addr: Address,
        demand_bytes: &alloy::primitives::Bytes,
    ) -> eyre::Result<DecodedDemand> {
        let addresses = &self.addresses;

        let decoded = if arbiter_addr == addresses.trivial_arbiter {
            DecodedDemand::TrivialArbiter

        // Core arbiters
        } else if arbiter_addr == addresses.specific_attestation_arbiter {
            let demand = demand_bytes.try_into()?;
            DecodedDemand::SpecificAttestation(demand)
        } else if arbiter_addr == addresses.trusted_party_arbiter {
            let demand: crate::contracts::TrustedPartyArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::TrustedParty(demand)
        } else if arbiter_addr == addresses.trusted_oracle_arbiter {
            let demand: crate::contracts::TrustedOracleArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::TrustedOracle(demand)
        } else if arbiter_addr == addresses.intrinsics_arbiter_2 {
            let demand: crate::contracts::IntrinsicsArbiter2::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::IntrinsicsArbiter2(demand)

        // Logical arbiters
        } else if arbiter_addr == addresses.any_arbiter {
            let demand: crate::contracts::logical::AnyArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::AnyArbiter(demand)
        } else if arbiter_addr == addresses.all_arbiter {
            let demand: crate::contracts::logical::AllArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::AllArbiter(demand)
        } else if arbiter_addr == addresses.not_arbiter {
            let demand: crate::contracts::logical::NotArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::NotArbiter(demand)

        // Confirmation arbiters (no demand data)
        } else if arbiter_addr == addresses.confirmation_arbiter {
            DecodedDemand::ConfirmationArbiter
        } else if arbiter_addr == addresses.confirmation_arbiter_composing {
            DecodedDemand::ConfirmationArbiterComposing
        } else if arbiter_addr == addresses.revocable_confirmation_arbiter {
            DecodedDemand::RevocableConfirmationArbiter
        } else if arbiter_addr == addresses.revocable_confirmation_arbiter_composing {
            DecodedDemand::RevocableConfirmationArbiterComposing
        } else if arbiter_addr == addresses.unrevocable_confirmation_arbiter {
            DecodedDemand::UnrevocableConfirmationArbiter
        } else if arbiter_addr == addresses.unrevocable_confirmation_arbiter_composing {
            DecodedDemand::UnrevocableConfirmationArbiterComposing

        // Payment fulfillment arbiters (no demand data)
        } else if arbiter_addr == addresses.erc20_payment_fulfillment_arbiter {
            DecodedDemand::ERC20PaymentFulfillmentArbiter
        } else if arbiter_addr == addresses.erc721_payment_fulfillment_arbiter {
            DecodedDemand::ERC721PaymentFulfillmentArbiter
        } else if arbiter_addr == addresses.erc1155_payment_fulfillment_arbiter {
            DecodedDemand::ERC1155PaymentFulfillmentArbiter
        } else if arbiter_addr == addresses.token_bundle_payment_fulfillment_arbiter {
            DecodedDemand::TokenBundlePaymentFulfillmentArbiter

        // Attestation property arbiters - composing
        } else if arbiter_addr == addresses.attester_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::AttesterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::AttesterArbiterComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_after_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::ExpirationTimeAfterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeAfterArbiterComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_before_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::ExpirationTimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeBeforeArbiterComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_equal_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::ExpirationTimeEqualArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeEqualArbiterComposing(demand)
        } else if arbiter_addr == addresses.recipient_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::RecipientArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RecipientArbiterComposing(demand)
        } else if arbiter_addr == addresses.ref_uid_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::RefUidArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RefUidArbiterComposing(demand)
        } else if arbiter_addr == addresses.revocable_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::RevocableArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RevocableArbiterComposing(demand)
        } else if arbiter_addr == addresses.schema_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::SchemaArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::SchemaArbiterComposing(demand)
        } else if arbiter_addr == addresses.time_after_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::TimeAfterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeAfterArbiterComposing(demand)
        } else if arbiter_addr == addresses.time_before_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::TimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeBeforeArbiterComposing(demand)
        } else if arbiter_addr == addresses.time_equal_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::TimeEqualArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeEqualArbiterComposing(demand)
        } else if arbiter_addr == addresses.uid_arbiter_composing {
            let demand: crate::contracts::attestation_properties::composing::UidArbiter::DemandData =
                demand_bytes.try_into()?;
            DecodedDemand::UidArbiterComposing(demand)

        // Attestation property arbiters - non-composing
        } else if arbiter_addr == addresses.attester_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::AttesterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::AttesterArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_after_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::ExpirationTimeAfterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeAfterArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_before_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::ExpirationTimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeBeforeArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.expiration_time_equal_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::ExpirationTimeEqualArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::ExpirationTimeEqualArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.recipient_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::RecipientArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RecipientArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.ref_uid_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::RefUidArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RefUidArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.revocable_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::RevocableArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::RevocableArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.schema_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::SchemaArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::SchemaArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.time_after_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::TimeAfterArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeAfterArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.time_before_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeBeforeArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.time_equal_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::TimeEqualArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::TimeEqualArbiterNonComposing(demand)
        } else if arbiter_addr == addresses.uid_arbiter_non_composing {
            let demand: crate::contracts::attestation_properties::non_composing::UidArbiter::DemandData = demand_bytes.try_into()?;
            DecodedDemand::UidArbiterNonComposing(demand)
        } else {
            DecodedDemand::Unknown {
                arbiter: arbiter_addr,
                raw_data: demand_bytes.clone(),
            }
        };

        Ok(decoded)
    }
}
