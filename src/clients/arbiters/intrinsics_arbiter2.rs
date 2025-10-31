use crate::{
    clients::arbiters::ArbitersModule, contracts::IntrinsicsArbiter2::DemandData, impl_arbiter_api,
    impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_intrinsics_arbiter2_demand,
    decode_intrinsics_arbiter2_demand
);

impl_arbiter_api!(
    IntrinsicsArbiter2,
    DemandData,
    encode_intrinsics_arbiter2_demand,
    decode_intrinsics_arbiter2_demand,
    intrinsics_arbiter_2
);
