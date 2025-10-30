use crate::arbiters::common::create_test_attestation;
use alkahest_rs::{
    clients::arbiters::{ArbitersModule, TrustedPartyArbiter},
    contracts,
    utils::setup_test_environment,
};
use alloy::primitives::{Address, Bytes, FixedBytes};

#[tokio::test]
async fn test_trusted_party_arbiter_with_incorrect_creator_original() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Create a test attestation
    let attestation = create_test_attestation(None, None);

    // Create demand data with the correct creator
    let demand_data = contracts::TrustedPartyArbiter::DemandData {
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
    let demand_data = contracts::TrustedPartyArbiter::DemandData {
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
