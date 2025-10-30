use alkahest_rs::{
    clients::arbiters::{
        ArbitersModule, IntrinsicsArbiter2, SpecificAttestationArbiter, TrustedOracleArbiter,
        TrustedPartyArbiter,
    }, contracts, utils::setup_test_environment
};
use alloy::primitives::{Address, Bytes, FixedBytes, bytes};

#[tokio::test]
async fn test_encode_and_decode_trusted_party_demand() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Create a test demand data
    let creator = Address::from_slice(&[0x01; 20]);
    let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;

    let demand_data = contracts::TrustedPartyArbiter::DemandData {
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
    let demand_data = contracts::SpecificAttestationArbiter::DemandData { uid };

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
    let demand_data = contracts::TrustedOracleArbiter::DemandData {
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
async fn test_encode_and_decode_intrinsics_arbiter2_demand() -> eyre::Result<()> {
    // Create a test demand data
    let schema = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let demand_data = contracts::IntrinsicsArbiter2::DemandData { schema };

    // Encode the demand data
    let encoded = ArbitersModule::encode_intrinsics_arbiter2_demand(&demand_data);

    // Decode the demand data
    let decoded = ArbitersModule::decode_intrinsics_arbiter2_demand(&encoded)?;

    // Verify decoded data
    assert_eq!(decoded.schema, schema, "Schema should match");

    Ok(())
}
