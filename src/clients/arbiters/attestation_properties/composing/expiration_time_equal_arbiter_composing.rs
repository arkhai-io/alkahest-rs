use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::composing::ExpirationTimeEqualArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_expiration_time_equal_arbiter_composing_demand,
    decode_expiration_time_equal_arbiter_composing_demand
);
impl_arbiter_api!(
    ExpirationTimeEqualArbiterComposing,
    DemandData,
    encode_expiration_time_equal_arbiter_composing_demand,
    decode_expiration_time_equal_arbiter_composing_demand,
    expiration_time_equal_arbiter_composing
);
