use crate::{
    clients::arbiters::ArbitersModule, contracts::logical::NotArbiter::DemandData,
    impl_arbiter_api, impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);
impl_arbiter_api!(
    NotArbiter,
    DemandData,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand,
    not_arbiter
);
