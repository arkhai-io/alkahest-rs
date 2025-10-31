use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_time_before_arbiter_non_composing_demand,
    decode_time_before_arbiter_non_composing_demand
);
impl_arbiter_api!(
    TimeBeforeArbiterNonComposing,
    DemandData,
    encode_time_before_arbiter_non_composing_demand,
    decode_time_before_arbiter_non_composing_demand,
    time_before_arbiter_non_composing
);
