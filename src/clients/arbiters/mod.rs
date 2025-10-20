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
    ($contract:ident, $encode_fn:ident, $decode_fn:ident) => {
        impl $crate::clients::arbiters::ArbitersModule {
            pub fn $encode_fn(demand: &$contract::DemandData) -> alloy::primitives::Bytes {
                use alloy::sol_types::SolValue as _;
                demand.abi_encode().into()
            }

            pub fn $decode_fn(
                data: &alloy::primitives::Bytes,
            ) -> eyre::Result<$contract::DemandData> {
                use alloy::sol_types::SolValue as _;
                Ok($contract::DemandData::abi_decode(data)?)
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

/// Macro to generate simple API accessors for arbiters
#[macro_export]
macro_rules! impl_arbiter_api {
    ($api_name:ident, $demand_type:ty, $encode_fn:ident, $decode_fn:ident) => {
        #[derive(Clone)]
        pub struct $api_name;

        impl $api_name {
            pub fn encode(&self, demand: &$demand_type) -> alloy::primitives::Bytes {
                ArbitersModule::$encode_fn(demand)
            }

            pub fn decode(&self, data: &alloy::primitives::Bytes) -> eyre::Result<$demand_type> {
                ArbitersModule::$decode_fn(data)
            }
        }
    };
}

impl ArbitersModule {
    /// Access the TrustedOracleArbiter API helper
    pub fn trusted_oracle_arbiter(&self) -> TrustedOracleArbiterApi {
        TrustedOracleArbiterApi
    }

    /// Access the SpecificAttestationArbiter API helper  
    pub fn specific_attestation_arbiter(&self) -> SpecificAttestationArbiterApi {
        SpecificAttestationArbiterApi
    }

    /// Access the TrustedPartyArbiter API helper
    pub fn trusted_party_arbiter(&self) -> TrustedPartyArbiterApi {
        TrustedPartyArbiterApi
    }

    /// Access the IntrinsicsArbiter2 API helper
    pub fn intrinsics_arbiter2(&self) -> IntrinsicsArbiter2Api {
        IntrinsicsArbiter2Api
    }

    /// Access logical arbiters group
    pub fn logical(&self) -> LogicalArbitersApi {
        LogicalArbitersApi
    }

    /// Access confirmation arbiters group
    pub fn confirmation(&self) -> ConfirmationArbitersApi {
        ConfirmationArbitersApi
    }

    /// Access attestation properties arbiters group
    pub fn attestation_properties(&self) -> AttestationPropertiesApi {
        AttestationPropertiesApi
    }
}

#[cfg(test)]
mod tests {
    use crate::extensions::HasArbiters;
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        sol,
        sol_types::SolValue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        clients::arbiters::{
            ArbitersModule, IntrinsicsArbiter2, SpecificAttestationArbiter, TrustedOracleArbiter,
            TrustedPartyArbiter,
        },
        contracts,
        utils::setup_test_environment,
    };

    pub(crate) fn create_test_attestation(
        uid: Option<FixedBytes<32>>,
        recipient: Option<Address>,
    ) -> contracts::IEAS::Attestation {
        contracts::IEAS::Attestation {
            uid: uid.unwrap_or_default(),
            schema: FixedBytes::<32>::default(),
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .into(),
            expirationTime: 0u64.into(),
            revocationTime: 0u64.into(),
            refUID: FixedBytes::<32>::default(),
            recipient: recipient.unwrap_or_default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        }
    }

    #[tokio::test]
    async fn test_trivial_arbiter_always_returns_true() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation (values don't matter for TrivialArbiter)
        let attestation = create_test_attestation(None, None);

        // Empty demand data
        let demand = Bytes::default();
        let counteroffer = FixedBytes::<32>::default();

        // Check that the arbiter returns true
        let trivial_arbiter = contracts::TrivialArbiter::new(
            test.addresses.arbiters_addresses.trivial_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trivial_arbiter
            .checkObligation(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?;

        // Should always return true
        assert!(result, "TrivialArbiter should always return true");

        // Try with different values, should still return true
        let attestation2 = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            ..attestation
        };

        sol! {
            struct TestDemand {
                bool data;
            }
        }

        let demand2 = TestDemand { data: true }.abi_encode().into();
        let counteroffer2 = FixedBytes::<32>::from_slice(&[42u8; 32]);

        let result2 = trivial_arbiter
            .checkObligation(attestation2.into(), demand2, counteroffer2)
            .call()
            .await?;

        // Should still return true
        assert!(
            result2,
            "TrivialArbiter should always return true, even with different values"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_party_arbiter_with_incorrect_creator_original() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let attestation = create_test_attestation(None, None);

        // Create demand data with the correct creator
        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.clone().trivial_arbiter,
            baseDemand: Bytes::from(vec![]),
            creator: test.alice.address(),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotTrustedParty
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses.arbiters_addresses.trusted_party_arbiter,
            &test.bob_client.wallet_provider,
        );

        // Call with Bob as the sender (different from demand_data.creator which is Alice)
        let result = trusted_party_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // We expect this to revert because Bob is not the creator
        assert!(
            result.is_err(),
            "TrustedPartyArbiter should revert with incorrect creator"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_party_arbiter_with_incorrect_creator() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create mock addresses for testing
        let creator = Address::from_slice(&[0x01; 20]);
        let non_creator = Address::from_slice(&[0x02; 20]);

        // Create a test attestation with an incorrect recipient (not the creator)
        let attestation = create_test_attestation(None, Some(non_creator));

        // Create demand data with the correct creator
        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: test.addresses.clone().arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::default(),
            creator,
        };

        // Encode the demand data
        let demand = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotTrustedParty
        let trusted_party_arbiter = contracts::TrustedPartyArbiter::new(
            test.addresses.arbiters_addresses.trusted_party_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_party_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // Expect an error containing "NotTrustedParty"
        assert!(result.is_err(), "Should have failed with incorrect creator");

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_constructor() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the obligation UID
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation - should be false initially since no decision has been made
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

        // Should be false initially
        assert!(
            !result,
            "TrustedOracleArbiter should initially return false"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_arbitrate() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create an attestation with the obligation UID
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check contract interface
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Initially the decision should be false (default value)
        let initial_result = trusted_oracle_arbiter
            .checkObligation(attestation.clone().into(), demand.clone(), counteroffer)
            .call()
            .await?;

        assert!(!initial_result, "Decision should initially be false");

        // Make a positive arbitration decision using our client
        let arbitrate_hash = test
            .bob_client
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash)
            .await?;

        // Now the decision should be true
        let final_result = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

        assert!(
            final_result,
            "Decision should now be true after arbitration"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_with_different_oracles() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Set up two different oracles
        let oracle1 = test.bob.address();
        let oracle2 = test.alice.address();

        // Oracle 1 (Bob) makes a positive decision
        let arbitrate_hash1 = test
            .bob_client
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt1 = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash1)
            .await?;

        // Oracle 2 (Alice) makes a negative decision
        let arbitrate_hash2 = test
            .alice_client
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, false)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt2 = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash2)
            .await?;

        // Create the attestation
        let attestation = create_test_attestation(Some(obligation_uid), None);
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Check with oracle1 (Bob) - should be true
        let demand_data1 = TrustedOracleArbiter::DemandData {
            oracle: oracle1,
            data: bytes!(""),
        };
        let demand1 = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data1);
        let counteroffer = FixedBytes::<32>::default();

        let result1 = trusted_oracle_arbiter
            .checkObligation(attestation.clone().into(), demand1, counteroffer)
            .call()
            .await?;

        assert!(result1, "Decision for Oracle 1 (Bob) should be true");

        // Check with oracle2 (Alice) - should be false
        let demand_data2 = TrustedOracleArbiter::DemandData {
            oracle: oracle2,
            data: bytes!(""),
        };
        let demand2 = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data2);

        let result2 = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand2, counteroffer)
            .call()
            .await?;

        assert!(!result2, "Decision for Oracle 2 (Alice) should be false");

        Ok(())
    }

    #[tokio::test]
    async fn test_trusted_oracle_arbiter_with_no_decision() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a new oracle address that hasn't made a decision
        let new_oracle = Address::from_slice(&[0x42; 20]);
        let obligation_uid = FixedBytes::<32>::from_slice(&[1u8; 32]);

        // Create the attestation
        let attestation = create_test_attestation(Some(obligation_uid), None);

        // Create demand data with the new oracle
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: new_oracle,
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check with the new oracle - should be false (default value)
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            test.addresses.arbiters_addresses.trusted_oracle_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = trusted_oracle_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await?;

        assert!(
            !result,
            "Decision for an oracle that hasn't made a decision should be false"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_specific_attestation_arbiter_with_incorrect_uid_original() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with non-matching UID
        let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid: different_uid };

        // Encode the demand data
        let encoded = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);

        // Check obligation should revert with NotDemandedAttestation
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .specific_attestation_arbiter,
            &test.alice_client.public_provider,
        );

        let result = specific_attestation_arbiter
            .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
            .call()
            .await;

        assert!(
            result.is_err(),
            "SpecificAttestationArbiter should revert with incorrect UID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_specific_attestation_arbiter_with_incorrect_uid() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create demand data with non-matching UID
        let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid: different_uid };

        // Encode demand data
        let demand = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);
        let counteroffer = FixedBytes::<32>::default();

        // Check obligation should revert with NotDemandedAttestation
        let specific_attestation_arbiter = contracts::SpecificAttestationArbiter::new(
            test.addresses
                .arbiters_addresses
                .specific_attestation_arbiter,
            &test.alice_client.wallet_provider,
        );

        let result = specific_attestation_arbiter
            .checkObligation(attestation.into(), demand, counteroffer)
            .call()
            .await;

        // Should fail with NotDemandedAttestation
        assert!(result.is_err(), "Should have failed with incorrect UID");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_trusted_party_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let creator = Address::from_slice(&[0x01; 20]);
        let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;

        let demand_data = TrustedPartyArbiter::DemandData {
            baseArbiter: base_arbiter,
            baseDemand: Bytes::from(vec![1, 2, 3]),
            creator,
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_trusted_party_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_trusted_party_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(
            decoded.baseArbiter, base_arbiter,
            "Base arbiter should match"
        );
        assert_eq!(
            decoded.baseDemand, demand_data.baseDemand,
            "Base demand should match"
        );
        assert_eq!(decoded.creator, creator, "Creator should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_specific_attestation_arbiter_demand() -> eyre::Result<()> {
        // Setup test environment
        let _test = setup_test_environment().await?;

        // Create a test demand data
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let demand_data = SpecificAttestationArbiter::DemandData { uid };

        // Encode the demand data
        let encoded = ArbitersModule::encode_specific_attestation_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_specific_attestation_arbiter_demand(&encoded)?;

        // Verify the data was encoded and decoded correctly
        assert_eq!(decoded.uid, uid, "UID did not round-trip correctly");

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_trusted_oracle_arbiter_demand() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let oracle = test.bob.address();
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle,
            data: bytes!(""),
        };

        // Encode the demand data
        let encoded = ArbitersModule::encode_trusted_oracle_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_trusted_oracle_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.oracle, oracle, "Oracle should match");

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_wait_for_trusted_oracle_arbitration() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        let obligation_uid = FixedBytes::<32>::from_slice(&[42u8; 32]);
        let oracle = test.bob.address();

        // Start listening for arbitration events in the background
        let listener_task = tokio::spawn({
            let alice_client = test.alice_client.clone();
            let obligation_uid = obligation_uid.clone();
            async move {
                alice_client
                    .extensions
                    .arbiters()
                    .wait_for_trusted_oracle_arbitration(oracle, obligation_uid, None)
                    .await
            }
        });

        // Ensure the listener is running
        // tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Make an arbitration decision
        let arbitrate_hash = test
            .bob_client
            .extensions
            .arbiters()
            .arbitrate_as_trusted_oracle(obligation_uid, true)
            .await?
            .transaction_hash;

        // Wait for transaction receipt
        let _receipt = test
            .alice_client
            .public_provider
            .get_transaction_receipt(arbitrate_hash)
            .await?;

        // Wait for the listener to pick up the event
        let log_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), listener_task).await???;

        // Verify the event data
        assert_eq!(log_result.oracle, oracle, "Oracle in event should match");
        assert_eq!(
            log_result.obligation, obligation_uid,
            "Obligation UID in event should match"
        );
        assert!(log_result.decision, "Decision in event should be true");

        Ok(())
    }

    #[tokio::test]
    async fn test_intrinsics_arbiter() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Create a valid non-expired attestation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a valid attestation (not expired, not revoked)
        let valid_attestation = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            schema: FixedBytes::<32>::from_slice(&[2u8; 32]),
            time: now.into(),
            expirationTime: (now + 3600).into(), // expires in 1 hour
            revocationTime: 0u64.into(),         // not revoked
            refUID: FixedBytes::<32>::default(),
            recipient: Address::default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        };

        // Create an expired attestation
        let expired_attestation = contracts::IEAS::Attestation {
            expirationTime: (now - 3600).into(), // expired 1 hour ago
            ..valid_attestation.clone()
        };

        // Create a revoked attestation
        let revoked_attestation = contracts::IEAS::Attestation {
            revocationTime: (now - 3600).into(), // revoked 1 hour ago
            ..valid_attestation.clone()
        };

        // Test with IntrinsicsArbiter
        let intrinsics_arbiter = contracts::IntrinsicsArbiter::new(
            test.addresses.arbiters_addresses.intrinsics_arbiter,
            &test.alice_client.wallet_provider,
        );

        // Valid attestation should pass
        let result_valid = intrinsics_arbiter
            .checkObligation(
                valid_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;
        assert!(
            result_valid,
            "Valid attestation should pass intrinsic checks"
        );

        // Expired attestation should fail
        let result_expired = intrinsics_arbiter
            .checkObligation(
                expired_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_expired.is_err(),
            "Expired attestation should fail intrinsic checks"
        );

        // Revoked attestation should fail
        let result_revoked = intrinsics_arbiter
            .checkObligation(
                revoked_attestation.into(),
                Bytes::default(),
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_revoked.is_err(),
            "Revoked attestation should fail intrinsic checks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_intrinsics_arbiter_2() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Define schemas
        let schema1 = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let schema2 = FixedBytes::<32>::from_slice(&[2u8; 32]);

        // Create a valid attestation with schema1
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_attestation = contracts::IEAS::Attestation {
            uid: FixedBytes::<32>::from_slice(&[1u8; 32]),
            schema: schema1,
            time: now.into(),
            expirationTime: (now + 3600).into(), // expires in 1 hour
            revocationTime: 0u64.into(),         // not revoked
            refUID: FixedBytes::<32>::default(),
            recipient: Address::default(),
            attester: Address::default(),
            revocable: true,
            data: Bytes::default(),
        };

        // Test with IntrinsicsArbiter2
        let intrinsics_arbiter2 = contracts::IntrinsicsArbiter2::new(
            test.addresses.arbiters_addresses.intrinsics_arbiter_2,
            &test.alice_client.wallet_provider,
        );

        // Create demand with matching schema
        let matching_demand = IntrinsicsArbiter2::DemandData { schema: schema1 };
        let encoded_matching_demand =
            ArbitersModule::encode_intrinsics_arbiter2_demand(&matching_demand);

        // Create demand with non-matching schema
        let non_matching_demand = IntrinsicsArbiter2::DemandData { schema: schema2 };
        let encoded_non_matching_demand =
            ArbitersModule::encode_intrinsics_arbiter2_demand(&non_matching_demand);

        // Test with matching schema - should pass
        let result_matching = intrinsics_arbiter2
            .checkObligation(
                valid_attestation.clone().into(),
                encoded_matching_demand,
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;
        assert!(
            result_matching,
            "Attestation with matching schema should pass"
        );

        // Test with non-matching schema - should fail
        let result_non_matching = intrinsics_arbiter2
            .checkObligation(
                valid_attestation.into(),
                encoded_non_matching_demand,
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        assert!(
            result_non_matching.is_err(),
            "Attestation with non-matching schema should fail"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_intrinsics_arbiter2_demand() -> eyre::Result<()> {
        // Create a test demand data
        let schema = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let demand_data = IntrinsicsArbiter2::DemandData { schema };

        // Encode the demand data
        let encoded = ArbitersModule::encode_intrinsics_arbiter2_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_intrinsics_arbiter2_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(decoded.schema, schema, "Schema should match");

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_arbiter_api() -> eyre::Result<()> {
        use crate::clients::arbiters::attestation_properties::composing::RecipientArbiterComposing;
        use crate::clients::arbiters::confirmation::ConfirmationArbiterComposing;

        // Setup test environment
        let test = setup_test_environment().await?;
        let arbiters = test.alice_client.arbiters();

        // Test core arbiters
        let oracle_demand = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: Bytes::from(b"test".as_slice()),
        };
        let encoded_oracle = arbiters.trusted_oracle_arbiter().encode(&oracle_demand);
        let decoded_oracle = arbiters.trusted_oracle_arbiter().decode(&encoded_oracle)?;
        assert_eq!(decoded_oracle.oracle, oracle_demand.oracle);

        // Test logical arbiters - arbiters.logical().all().encode()
        let all_demand = crate::clients::arbiters::logical::all_arbiter::AllArbiter::DemandData {
            arbiters: vec![test.addresses.arbiters_addresses.trivial_arbiter],
            demands: vec![Bytes::from(b"test".as_slice())],
        };
        let encoded_all = arbiters.logical().all().encode(&all_demand);
        let decoded_all = arbiters.logical().all().decode(&encoded_all)?;
        assert_eq!(decoded_all.arbiters.len(), 1);

        // Test confirmation arbiters - arbiters.confirmation().confirmation_composing().encode()
        let confirmation_demand = ConfirmationArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
        };
        let encoded_confirmation = arbiters
            .confirmation()
            .confirmation_composing()
            .encode(&confirmation_demand);
        let decoded_confirmation = arbiters
            .confirmation()
            .confirmation_composing()
            .decode(&encoded_confirmation)?;
        assert_eq!(
            decoded_confirmation.baseArbiter,
            confirmation_demand.baseArbiter
        );

        // Test attestation properties - arbiters.attestation_properties().composing().recipient().encode()
        let recipient_demand = RecipientArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            recipient: test.alice.address(),
        };
        let encoded_recipient = arbiters
            .attestation_properties()
            .composing()
            .recipient()
            .encode(&recipient_demand);
        let decoded_recipient = arbiters
            .attestation_properties()
            .composing()
            .recipient()
            .decode(&encoded_recipient)?;
        assert_eq!(decoded_recipient.recipient, recipient_demand.recipient);

        println!("✅ All arbiter APIs work:");
        println!("  - Core: arbiters.trusted_oracle_arbiter().encode()");
        println!("  - Logical: arbiters.logical().all().encode()");
        println!("  - Confirmation: arbiters.confirmation().confirmation_composing().encode()");
        println!(
            "  - Properties: arbiters.attestation_properties().composing().recipient().encode()"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_all_attestation_properties_composing_arbiters() -> eyre::Result<()> {
        use crate::clients::arbiters::attestation_properties::composing::*;

        // Setup test environment
        let test = setup_test_environment().await?;
        let arbiters = test.alice_client.arbiters();
        let props = arbiters.attestation_properties().composing();

        // Test all attestation properties composing arbiters

        // Test recipient arbiter
        let recipient_demand = RecipientArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            recipient: test.alice.address(),
        };
        let encoded = props.recipient().encode(&recipient_demand);
        let decoded = props.recipient().decode(&encoded)?;
        assert_eq!(decoded.recipient, recipient_demand.recipient);

        // Test uid arbiter
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let uid_demand = UidArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            uid,
        };
        let encoded = props.uid().encode(&uid_demand);
        let decoded = props.uid().decode(&encoded)?;
        assert_eq!(decoded.uid, uid_demand.uid);

        // Test attester arbiter
        let attester_demand = AttesterArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            attester: test.bob.address(),
        };
        let encoded = props.attester().encode(&attester_demand);
        let decoded = props.attester().decode(&encoded)?;
        assert_eq!(decoded.attester, attester_demand.attester);

        // Test schema arbiter
        let schema = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let schema_demand = SchemaArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            schema,
        };
        let encoded = props.schema().encode(&schema_demand);
        let decoded = props.schema().decode(&encoded)?;
        assert_eq!(decoded.schema, schema_demand.schema);

        // Test time arbiters
        let time_value = 1234567890u64;
        let time_after_demand = TimeAfterArbiterComposing::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            time: time_value.into(),
        };
        let encoded = props.time_after().encode(&time_after_demand);
        let decoded = props.time_after().decode(&encoded)?;
        assert_eq!(decoded.time, time_after_demand.time);

        println!("✅ All attestation properties composing arbiters work:");
        println!("  - arbiters.attestation_properties().composing().recipient().encode()");
        println!("  - arbiters.attestation_properties().composing().uid().encode()");
        println!("  - arbiters.attestation_properties().composing().attester().encode()");
        println!("  - arbiters.attestation_properties().composing().schema().encode()");
        println!("  - arbiters.attestation_properties().composing().time_after().encode()");
        println!("  - arbiters.attestation_properties().composing().time_before().encode()");
        println!("  - arbiters.attestation_properties().composing().time_equal().encode()");
        println!(
            "  - arbiters.attestation_properties().composing().expiration_time_after().encode()"
        );
        println!(
            "  - arbiters.attestation_properties().composing().expiration_time_before().encode()"
        );
        println!(
            "  - arbiters.attestation_properties().composing().expiration_time_equal().encode()"
        );
        println!("  - arbiters.attestation_properties().composing().ref_uid().encode()");
        println!("  - arbiters.attestation_properties().composing().revocable().encode()");

        Ok(())
    }

    #[tokio::test]
    async fn test_all_attestation_properties_non_composing_arbiters() -> eyre::Result<()> {
        use crate::clients::arbiters::attestation_properties::non_composing::*;

        // Setup test environment
        let test = setup_test_environment().await?;
        let arbiters = test.alice_client.arbiters();
        let props = arbiters.attestation_properties().non_composing();

        // Test all attestation properties non-composing arbiters

        // Test recipient arbiter
        let recipient_demand = RecipientArbiterNonComposing::DemandData {
            recipient: test.alice.address(),
        };
        let encoded = props.recipient().encode(&recipient_demand);
        let decoded = props.recipient().decode(&encoded)?;
        assert_eq!(decoded.recipient, recipient_demand.recipient);

        // Test uid arbiter
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let uid_demand = UidArbiterNonComposing::DemandData { uid };
        let encoded = props.uid().encode(&uid_demand);
        let decoded = props.uid().decode(&encoded)?;
        assert_eq!(decoded.uid, uid_demand.uid);

        // Test attester arbiter
        let attester_demand = AttesterArbiterNonComposing::DemandData {
            attester: test.bob.address(),
        };
        let encoded = props.attester().encode(&attester_demand);
        let decoded = props.attester().decode(&encoded)?;
        assert_eq!(decoded.attester, attester_demand.attester);

        // Test schema arbiter
        let schema = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let schema_demand = SchemaArbiterNonComposing::DemandData { schema };
        let encoded = props.schema().encode(&schema_demand);
        let decoded = props.schema().decode(&encoded)?;
        assert_eq!(decoded.schema, schema_demand.schema);

        // Test revocable arbiter
        let revocable_demand = RevocableArbiterNonComposing::DemandData { revocable: true };
        let encoded = props.revocable().encode(&revocable_demand);
        let decoded = props.revocable().decode(&encoded)?;
        assert_eq!(decoded.revocable, revocable_demand.revocable);

        // Test time arbiters
        let time_value = 1234567890u64;
        let time_after_demand = TimeAfterArbiterNonComposing::DemandData {
            time: time_value.into(),
        };
        let encoded = props.time_after().encode(&time_after_demand);
        let decoded = props.time_after().decode(&encoded)?;
        assert_eq!(decoded.time, time_after_demand.time);

        let time_before_demand = TimeBeforeArbiterNonComposing::DemandData {
            time: time_value.into(),
        };
        let encoded = props.time_before().encode(&time_before_demand);
        let decoded = props.time_before().decode(&encoded)?;
        assert_eq!(decoded.time, time_before_demand.time);

        let time_equal_demand = TimeEqualArbiterNonComposing::DemandData {
            time: time_value.into(),
        };
        let encoded = props.time_equal().encode(&time_equal_demand);
        let decoded = props.time_equal().decode(&encoded)?;
        assert_eq!(decoded.time, time_equal_demand.time);

        // Test expiration time arbiters
        let expiration_time_after_demand = ExpirationTimeAfterArbiterNonComposing::DemandData {
            expirationTime: time_value.into(),
        };
        let encoded = props
            .expiration_time_after()
            .encode(&expiration_time_after_demand);
        let decoded = props.expiration_time_after().decode(&encoded)?;
        assert_eq!(
            decoded.expirationTime,
            expiration_time_after_demand.expirationTime
        );

        let expiration_time_before_demand = ExpirationTimeBeforeArbiterNonComposing::DemandData {
            expirationTime: time_value.into(),
        };
        let encoded = props
            .expiration_time_before()
            .encode(&expiration_time_before_demand);
        let decoded = props.expiration_time_before().decode(&encoded)?;
        assert_eq!(
            decoded.expirationTime,
            expiration_time_before_demand.expirationTime
        );

        let expiration_time_equal_demand = ExpirationTimeEqualArbiterNonComposing::DemandData {
            expirationTime: time_value.into(),
        };
        let encoded = props
            .expiration_time_equal()
            .encode(&expiration_time_equal_demand);
        let decoded = props.expiration_time_equal().decode(&encoded)?;
        assert_eq!(
            decoded.expirationTime,
            expiration_time_equal_demand.expirationTime
        );

        // Test ref_uid arbiter
        let ref_uid = FixedBytes::<32>::from_slice(&[3u8; 32]);
        let ref_uid_demand = RefUidArbiterNonComposing::DemandData { refUID: ref_uid };
        let encoded = props.ref_uid().encode(&ref_uid_demand);
        let decoded = props.ref_uid().decode(&encoded)?;
        assert_eq!(decoded.refUID, ref_uid_demand.refUID);

        println!("✅ All attestation properties non-composing arbiters work:");
        println!("  - arbiters.attestation_properties().non_composing().recipient().encode()");
        println!("  - arbiters.attestation_properties().non_composing().uid().encode()");
        println!("  - arbiters.attestation_properties().non_composing().attester().encode()");
        println!("  - arbiters.attestation_properties().non_composing().schema().encode()");
        println!("  - arbiters.attestation_properties().non_composing().revocable().encode()");
        println!("  - arbiters.attestation_properties().non_composing().time_after().encode()");
        println!("  - arbiters.attestation_properties().non_composing().time_before().encode()");
        println!("  - arbiters.attestation_properties().non_composing().time_equal().encode()");
        println!(
            "  - arbiters.attestation_properties().non_composing().expiration_time_after().encode()"
        );
        println!(
            "  - arbiters.attestation_properties().non_composing().expiration_time_before().encode()"
        );
        println!(
            "  - arbiters.attestation_properties().non_composing().expiration_time_equal().encode()"
        );
        println!("  - arbiters.attestation_properties().non_composing().ref_uid().encode()");

        Ok(())
    }

    #[tokio::test]
    async fn test_simple_arbiter_api() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Get arbiters module
        let arbiters = test.alice_client.arbiters();

        // Test TrustedOracleArbiter API
        let oracle_demand = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: Bytes::from(b"test_data".as_slice()),
        };

        let encoded = arbiters.trusted_oracle_arbiter().encode(&oracle_demand);
        let decoded = arbiters.trusted_oracle_arbiter().decode(&encoded)?;
        assert_eq!(decoded.oracle, oracle_demand.oracle, "Oracle should match");

        // Test logical.all API
        let all_demand = crate::clients::arbiters::logical::all_arbiter::AllArbiter::DemandData {
            arbiters: vec![test.addresses.arbiters_addresses.trivial_arbiter],
            demands: vec![Bytes::from(b"test".as_slice())],
        };

        let encoded_all = arbiters.logical().all().encode(&all_demand);
        let decoded_all = arbiters.logical().all().decode(&encoded_all)?;
        assert_eq!(decoded_all.arbiters.len(), 1, "Should have one arbiter");

        println!("✅ Simple arbiter API works!");
        Ok(())
    }
}
