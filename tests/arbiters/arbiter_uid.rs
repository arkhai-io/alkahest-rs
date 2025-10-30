use alkahest_rs::{
    clients::arbiters::{ArbitersModule, attestation_properties::composing::UidArbiterComposing},
    contracts,
    utils::setup_test_environment,
};
use alloy::primitives::{Address, Bytes, FixedBytes};
use std::time::{SystemTime, UNIX_EPOCH};

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
async fn test_uid_arbiter_with_incorrect_uid() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Create a test attestation
    let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let attestation = create_test_attestation(Some(uid), None);

    // Create demand data with non-matching UID
    let different_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
    let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
    let demand_data = contracts::attestation_properties::composing::UidArbiter::DemandData {
        baseArbiter: trivial_arbiter,
        baseDemand: Bytes::default(),
        uid: different_uid,
    };

    // Encode the demand data
    let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

    // Check obligation should revert with UidMismatched
    let uid_arbiter_address = test.addresses.arbiters_addresses.clone().uid_arbiter;
    let uid_arbiter = contracts::attestation_properties::composing::UidArbiterComposing::new(
        uid_arbiter_address,
        &test.alice_client.public_provider,
    );

    let result = uid_arbiter
        .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
        .call()
        .await;

    assert!(
        result.is_err(),
        "UidArbiter should revert with incorrect UID"
    );

    Ok(())
}

#[tokio::test]
async fn test_uid_arbiter_with_correct_uid() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Create a test attestation
    let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let attestation = create_test_attestation(Some(uid), None);

    // Create demand data with matching UID and use trivialArbiter as the baseArbiter
    let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
    let demand_data = contracts::attestation_properties::composing::UidArbiter::DemandData {
        baseArbiter: trivial_arbiter,
        baseDemand: Bytes::default(),
        uid,
    };

    // Encode the demand data
    let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

    // Check obligation - should return true
    let uid_arbiter_address = test.addresses.arbiters_addresses.clone().uid_arbiter;
    let uid_arbiter = contracts::attestation_properties::composing::UidArbiterComposing::new(
        uid_arbiter_address,
        &test.alice_client.public_provider,
    );
    let result = uid_arbiter
        .checkObligation(attestation.clone().into(), encoded, FixedBytes::<32>::ZERO)
        .call()
        .await?;

    assert!(result, "UidArbiter should return true with matching UID");

    Ok(())
}

#[tokio::test]
async fn test_encode_and_decode_uid_arbiter_composing_demand() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Create a test demand data
    let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let trivial_arbiter = test.addresses.arbiters_addresses.clone().trivial_arbiter;
    let demand_data = contracts::attestation_properties::composing::UidArbiter::DemandData {
        baseArbiter: trivial_arbiter,
        baseDemand: Bytes::default(),
        uid,
    };

    // Encode the demand data
    let encoded = ArbitersModule::encode_uid_arbiter_composing_demand(&demand_data);

    // Decode the demand data
    let decoded = ArbitersModule::decode_uid_arbiter_composing_demand(&encoded)?;

    // Verify the data was encoded and decoded correctly
    assert_eq!(decoded.uid, uid, "UID did not round-trip correctly");

    Ok(())
}
