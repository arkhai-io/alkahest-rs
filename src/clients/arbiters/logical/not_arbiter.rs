use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract NotArbiter {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

crate::impl_encode_and_decode!(
    NotArbiter,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    NotArbiterApi,
    NotArbiter::DemandData,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::setup_test_environment;
    use alloy::primitives::Bytes;

    #[tokio::test]
    async fn test_encode_and_decode_not_arbiter_demand() -> eyre::Result<()> {
        // Set up test environment
        let test = setup_test_environment().await?;

        // Create a test demand data
        let base_arbiter = test.addresses.arbiters_addresses.trivial_arbiter;
        let base_demand = Bytes::from(vec![1, 2, 3, 4, 5]);

        let demand_data = NotArbiter::DemandData {
            baseArbiter: base_arbiter,
            baseDemand: base_demand.clone(),
        };

        // Encode the demand data
        let encoded =
            crate::clients::arbiters::ArbitersModule::encode_not_arbiter_demand(&demand_data);

        // Decode the demand data
        let decoded =
            crate::clients::arbiters::ArbitersModule::decode_not_arbiter_demand(&encoded)?;

        // Verify decoded data
        assert_eq!(
            decoded.baseArbiter, base_arbiter,
            "Base arbiter should match"
        );
        assert_eq!(decoded.baseDemand, base_demand, "Base demand should match");

        Ok(())
    }
}
