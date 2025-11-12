use alloy::primitives::Address;

use crate::{
    clients::arbiters::{ArbitersModule, DecodedDemand}, contracts::logical::AnyArbiter::DemandData,
    impl_arbiter_api, impl_demand_data_conversions, impl_encode_and_decode,
};

impl_demand_data_conversions!(DemandData);

/// Decoded version of AnyArbiter::DemandData with actual demand structures instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedAnyArbiterDemandData {
    /// Same arbiters vector as original
    pub arbiters: Vec<Address>,
    /// Decoded demands instead of raw bytes
    pub demands: Vec<DecodedDemand>,
}

impl ArbitersModule {
    pub fn decode_any_arbiter_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedAnyArbiterDemandData> {
        if demand_data.arbiters.len() != demand_data.demands.len() {
            return Err(eyre::eyre!(
                "AnyArbiter has mismatched arrays: {} arbiters vs {} demands",
                demand_data.arbiters.len(),
                demand_data.demands.len()
            ));
        }

        let arbiters = demand_data.arbiters.clone();
        let mut decoded_demands = Vec::new();

        for (arbiter_addr, demand_bytes) in
            demand_data.arbiters.iter().zip(demand_data.demands.iter())
        {
            let decoded = self.decode_arbiter_demand(*arbiter_addr, demand_bytes)?;
            decoded_demands.push(decoded);
        }

        Ok(DecodedAnyArbiterDemandData {
            arbiters,
            demands: decoded_demands,
        })
    }
}
