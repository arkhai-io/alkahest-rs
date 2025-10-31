use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::TimeEqualArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_time_equal_arbiter_non_composing_demand,
    decode_time_equal_arbiter_non_composing_demand
);

impl_arbiter_api!(
    TimeEqualArbiterNonComposing,
    DemandData,
    encode_time_equal_arbiter_non_composing_demand,
    decode_time_equal_arbiter_non_composing_demand,
    time_equal_arbiter_non_composing
);
