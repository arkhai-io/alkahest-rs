use crate::{clients::arbiters::ArbitersModule, contracts::logical::AnyArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_any_arbiter_demand,
    decode_any_arbiter_demand
);
impl_arbiter_api!(
    AnyArbiter,
    DemandData,
    encode_any_arbiter_demand,
    decode_any_arbiter_demand,
    any_arbiter
);
