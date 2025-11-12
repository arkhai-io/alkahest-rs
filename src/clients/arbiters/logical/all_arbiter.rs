use crate::{
    clients::arbiters::ArbitersModule, contracts, contracts::logical::AllArbiter::DemandData,
    impl_arbiter_api, impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::{Address, Bytes};
use alloy::sol_types::SolValue;

impl_demand_data_conversions!(DemandData);

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
        raw_data: Bytes,
    },
}

/// Decoded version of AllArbiter::DemandData with actual demand structures instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedAllArbiterDemandData {
    /// Same arbiters vector as original
    pub arbiters: Vec<Address>,
    /// Decoded demands instead of raw bytes
    pub demands: Vec<DecodedDemand>,
}

impl ArbitersModule {
    pub fn decode_all_arbiter_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedAllArbiterDemandData> {
        if demand_data.arbiters.len() != demand_data.demands.len() {
            return Err(eyre::eyre!(
                "AllArbiter has mismatched arrays: {} arbiters vs {} demands",
                demand_data.arbiters.len(),
                demand_data.demands.len()
            ));
        }

        let arbiters = demand_data.arbiters.clone();
        let mut decoded_demands = Vec::new();
        let addresses = &self.addresses;

        for (arbiter_addr, demand_bytes) in
            demand_data.arbiters.iter().zip(demand_data.demands.iter())
        {
            let decoded = if *arbiter_addr == addresses.trivial_arbiter {
                DecodedDemand::TrivialArbiter

            // Core arbiters
            } else if *arbiter_addr == addresses.specific_attestation_arbiter {
                let demand: contracts::SpecificAttestationArbiter::DemandData =
                    demand_bytes.try_into()?;
                DecodedDemand::SpecificAttestation(demand)
            } else if *arbiter_addr == addresses.trusted_party_arbiter {
                let demand: contracts::TrustedPartyArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TrustedParty(demand)
            } else if *arbiter_addr == addresses.trusted_oracle_arbiter {
                let demand: contracts::TrustedOracleArbiter::DemandData =
                    demand_bytes.try_into()?;
                DecodedDemand::TrustedOracle(demand)
            } else if *arbiter_addr == addresses.intrinsics_arbiter_2 {
                let demand: contracts::IntrinsicsArbiter2::DemandData = demand_bytes.try_into()?;
                DecodedDemand::IntrinsicsArbiter2(demand)

            // Logical arbiters
            } else if *arbiter_addr == addresses.any_arbiter {
                let demand: contracts::logical::AnyArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::AnyArbiter(demand)
            } else if *arbiter_addr == addresses.all_arbiter {
                let demand: contracts::logical::AllArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::AllArbiter(demand)
            } else if *arbiter_addr == addresses.not_arbiter {
                let demand: contracts::logical::NotArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::NotArbiter(demand)

            // Confirmation arbiters (no demand data)
            } else if *arbiter_addr == addresses.confirmation_arbiter {
                DecodedDemand::ConfirmationArbiter
            } else if *arbiter_addr == addresses.confirmation_arbiter_composing {
                DecodedDemand::ConfirmationArbiterComposing
            } else if *arbiter_addr == addresses.revocable_confirmation_arbiter {
                DecodedDemand::RevocableConfirmationArbiter
            } else if *arbiter_addr == addresses.revocable_confirmation_arbiter_composing {
                DecodedDemand::RevocableConfirmationArbiterComposing
            } else if *arbiter_addr == addresses.unrevocable_confirmation_arbiter {
                DecodedDemand::UnrevocableConfirmationArbiter
            } else if *arbiter_addr == addresses.unrevocable_confirmation_arbiter_composing {
                DecodedDemand::UnrevocableConfirmationArbiterComposing

                // Payment fulfillment arbiters (no demand data)
            } else if *arbiter_addr == addresses.erc20_payment_fulfillment_arbiter {
                DecodedDemand::ERC20PaymentFulfillmentArbiter
            } else if *arbiter_addr == addresses.erc721_payment_fulfillment_arbiter {
                DecodedDemand::ERC721PaymentFulfillmentArbiter
            } else if *arbiter_addr == addresses.erc1155_payment_fulfillment_arbiter {
                DecodedDemand::ERC1155PaymentFulfillmentArbiter
            } else if *arbiter_addr == addresses.token_bundle_payment_fulfillment_arbiter {
                DecodedDemand::TokenBundlePaymentFulfillmentArbiter

            // Attestation property arbiters - composing
            } else if *arbiter_addr == addresses.attester_arbiter_composing {
                let demand: contracts::attestation_properties::composing::AttesterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::AttesterArbiterComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_after_arbiter_composing {
                let demand: contracts::attestation_properties::composing::ExpirationTimeAfterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeAfterArbiterComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_before_arbiter_composing {
                let demand: contracts::attestation_properties::composing::ExpirationTimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeBeforeArbiterComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_equal_arbiter_composing {
                let demand: contracts::attestation_properties::composing::ExpirationTimeEqualArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeEqualArbiterComposing(demand)
            } else if *arbiter_addr == addresses.recipient_arbiter_composing {
                let demand: contracts::attestation_properties::composing::RecipientArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RecipientArbiterComposing(demand)
            } else if *arbiter_addr == addresses.ref_uid_arbiter_composing {
                let demand: contracts::attestation_properties::composing::RefUidArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RefUidArbiterComposing(demand)
            } else if *arbiter_addr == addresses.revocable_arbiter_composing {
                let demand: contracts::attestation_properties::composing::RevocableArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RevocableArbiterComposing(demand)
            } else if *arbiter_addr == addresses.schema_arbiter_composing {
                let demand: contracts::attestation_properties::composing::SchemaArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::SchemaArbiterComposing(demand)
            } else if *arbiter_addr == addresses.time_after_arbiter_composing {
                let demand: contracts::attestation_properties::composing::TimeAfterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeAfterArbiterComposing(demand)
            } else if *arbiter_addr == addresses.time_before_arbiter_composing {
                let demand: contracts::attestation_properties::composing::TimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeBeforeArbiterComposing(demand)
            } else if *arbiter_addr == addresses.time_equal_arbiter_composing {
                let demand: contracts::attestation_properties::composing::TimeEqualArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeEqualArbiterComposing(demand)
            } else if *arbiter_addr == addresses.uid_arbiter_composing {
                let demand: contracts::attestation_properties::composing::UidArbiter::DemandData =
                    demand_bytes.try_into()?;
                DecodedDemand::UidArbiterComposing(demand)

            // Attestation property arbiters - non-composing
            } else if *arbiter_addr == addresses.attester_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::AttesterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::AttesterArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_after_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::ExpirationTimeAfterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeAfterArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_before_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::ExpirationTimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeBeforeArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.expiration_time_equal_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::ExpirationTimeEqualArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::ExpirationTimeEqualArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.recipient_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::RecipientArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RecipientArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.ref_uid_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::RefUidArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RefUidArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.revocable_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::RevocableArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::RevocableArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.schema_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::SchemaArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::SchemaArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.time_after_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::TimeAfterArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeAfterArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.time_before_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeBeforeArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.time_equal_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::TimeEqualArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::TimeEqualArbiterNonComposing(demand)
            } else if *arbiter_addr == addresses.uid_arbiter_non_composing {
                let demand: contracts::attestation_properties::non_composing::UidArbiter::DemandData = demand_bytes.try_into()?;
                DecodedDemand::UidArbiterNonComposing(demand)
            } else {
                DecodedDemand::Unknown {
                    arbiter: *arbiter_addr,
                    raw_data: demand_bytes.clone(),
                }
            };

            decoded_demands.push(decoded);
        }

        Ok(DecodedAllArbiterDemandData {
            arbiters,
            demands: decoded_demands,
        })
    }
}
