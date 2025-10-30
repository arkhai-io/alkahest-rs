use alkahest_rs::{
    clients::arbiters::{ArbitersModule, logical::not_arbiter::NotArbiter}, contracts, utils::setup_test_environment
};
use alloy::primitives::{Address, Bytes, FixedBytes};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn create_test_attestation(
    uid: Option<FixedBytes<32>>,
    recipient: Option<Address>,
) -> alkahest_rs::contracts::IEAS::Attestation {
    alkahest_rs::contracts::IEAS::Attestation {
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
async fn test_encode_and_decode_not_arbiter_demand() -> eyre::Result<()> {
    // Set up test environment
    let test = setup_test_environment().await?;

    // Create a test demand data
    let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;
    let base_demand = Bytes::from(vec![1, 2, 3, 4, 5]);

    let demand_data = contracts::logical::NotArbiter::DemandData {
        baseArbiter: base_arbiter,
        baseDemand: base_demand.clone(),
    };

    // Encode the demand data
    let encoded = ArbitersModule::encode_not_arbiter_demand(&demand_data);

    // Decode the demand data
    let decoded = ArbitersModule::decode_not_arbiter_demand(&encoded)?;

    // Verify decoded data
    assert_eq!(
        decoded.baseArbiter, base_arbiter,
        "Base arbiter should match"
    );
    assert_eq!(decoded.baseDemand, base_demand, "Base demand should match");

    Ok(())
}
