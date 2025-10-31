use crate::{
    clients::arbiters::ArbitersModule, contracts::logical::AllArbiter::DemandData, impl_arbiter_api,
    impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);
impl_arbiter_api!(
    AllArbiter,
    DemandData,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand,
    all_arbiter
);
