use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule, contracts::logical::NotArbiter::DemandData,
    impl_arbiter_api, impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of NotArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedNotArbiterDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: DecodedDemand,
}

impl ArbitersModule {
    pub fn decode_not_arbiter_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedNotArbiterDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedNotArbiterDemandData {
            base_arbiter,
            base_demand: decoded_base_demand,
        })
    }
}
