use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract AllArbiter {
        struct DemandData {
            address[] arbiters;
            bytes[] demands;
        }
    }
}

crate::impl_encode_and_decode!(
    AllArbiter,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    AllArbiterApi,
    AllArbiter::DemandData,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clients::arbiters::{ArbitersModule, SpecificAttestationArbiter},
        contracts,
        utils::setup_test_environment,
    };
    use alloy::primitives::{Bytes, FixedBytes};

    // Import create_test_attestation from the parent test module
    use crate::clients::arbiters::tests::create_test_attestation;

    #[tokio::test]
    async fn test_all_arbiter() -> eyre::Result<()> {
        // Setup test environment
        let test = setup_test_environment().await?;

        // Get arbiter addresses
        let addresses = test.addresses.arbiters_addresses;

        // Create a test attestation
        let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
        let attestation = create_test_attestation(Some(uid), None);

        // Create different demand data for different arbiters

        // SpecificAttestationArbiter with matching UID (will return true)
        let specific_matching = SpecificAttestationArbiter::DemandData { uid };
        let specific_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_matching);

        // SpecificAttestationArbiter with non-matching UID (will return false/error)
        let non_matching_uid = FixedBytes::<32>::from_slice(&[2u8; 32]);
        let specific_non_matching = SpecificAttestationArbiter::DemandData {
            uid: non_matching_uid,
        };
        let specific_non_matching_encoded =
            ArbitersModule::encode_specific_attestation_arbiter_demand(&specific_non_matching);

        // Set up AllArbiter
        let all_arbiter =
            contracts::AllArbiter::new(addresses.all_arbiter, &test.alice_client.wallet_provider);

        // Test case 1: One true, one false - should return false
        let all_demand_data1 = AllArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return false with non-matching UID
            ],
            demands: vec![
                Bytes::default(),                      // Empty data for TrivialArbiter
                specific_non_matching_encoded.clone(), // Non-matching UID for SpecificAttestationArbiter
            ],
        };

        let all_demand1 = ArbitersModule::encode_all_arbiter_demand(&all_demand_data1);
        let result_all1 = all_arbiter
            .checkObligation(
                attestation.clone().into(),
                all_demand1,
                FixedBytes::<32>::default(),
            )
            .call()
            .await;

        // Should fail since one arbiter would fail
        assert!(
            result_all1.is_err(),
            "AllArbiter should return false if any arbiter returns false"
        );

        // Test case 2: All true - should return true
        let all_demand_data2 = AllArbiter::DemandData {
            arbiters: vec![
                addresses.trivial_arbiter,              // Always returns true
                addresses.specific_attestation_arbiter, // Will return true with matching UID
            ],
            demands: vec![
                Bytes::default(),          // Empty data for TrivialArbiter
                specific_matching_encoded, // Matching UID for SpecificAttestationArbiter
            ],
        };

        let all_demand2 = ArbitersModule::encode_all_arbiter_demand(&all_demand_data2);
        let result_all2 = all_arbiter
            .checkObligation(
                attestation.clone().into(),
                all_demand2,
                FixedBytes::<32>::default(),
            )
            .call()
            .await?;

        assert!(
            result_all2,
            "AllArbiter should return true if all arbiters return true"
        );

        // Test case 3: Empty arbiters list - should return true (vacuously true)
        let all_demand_data3 = AllArbiter::DemandData {
            arbiters: vec![],
            demands: vec![],
        };

        let all_demand3 = ArbitersModule::encode_all_arbiter_demand(&all_demand_data3);
        let result_all3 = all_arbiter
            .checkObligation(attestation.into(), all_demand3, FixedBytes::<32>::default())
            .call()
            .await?;

        assert!(
            result_all3,
            "AllArbiter should return true with empty arbiters list"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_encode_and_decode_all_arbiter_demand() -> eyre::Result<()> {
        // Set up test environment
        let test = setup_test_environment().await?;

        // Get arbiter addresses
        let addresses = test.addresses.arbiters_addresses;

        // Create a test demand data
        let arbiters = vec![
            addresses.trivial_arbiter,
            addresses.specific_attestation_arbiter,
        ];
        let demands = vec![Bytes::default(), Bytes::from(vec![1, 2, 3])];

        let demand_data = AllArbiter::DemandData { arbiters, demands };

        // Encode the demand data
        let encoded = ArbitersModule::encode_all_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded = ArbitersModule::decode_all_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(
            decoded.arbiters.len(),
            demand_data.arbiters.len(),
            "Number of arbiters should match"
        );
        assert_eq!(
            decoded.demands.len(),
            demand_data.demands.len(),
            "Number of demands should match"
        );

        for i in 0..decoded.arbiters.len() {
            assert_eq!(
                decoded.arbiters[i], demand_data.arbiters[i],
                "Arbiter address should match"
            );
            assert_eq!(
                decoded.demands[i], demand_data.demands[i],
                "Demand data should match"
            );
        }

        Ok(())
    }
}
