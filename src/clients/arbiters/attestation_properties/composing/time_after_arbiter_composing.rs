use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::composing::TimeAfterArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_time_after_arbiter_composing_demand,
    decode_time_after_arbiter_composing_demand
);
impl_arbiter_api!(
    TimeAfterArbiterComposing,
    DemandData,
    encode_time_after_arbiter_composing_demand,
    decode_time_after_arbiter_composing_demand,
    time_after_arbiter_composing
);
