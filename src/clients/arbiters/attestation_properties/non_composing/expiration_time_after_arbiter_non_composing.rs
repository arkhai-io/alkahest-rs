use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::ExpirationTimeAfterArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_expiration_time_after_arbiter_non_composing_demand,
    decode_expiration_time_after_arbiter_non_composing_demand
);
impl_arbiter_api!(
    ExpirationTimeAfterArbiterNonComposing,
    DemandData,
    encode_expiration_time_after_arbiter_non_composing_demand,
    decode_expiration_time_after_arbiter_non_composing_demand,
    expiration_time_after_arbiter_non_composing
);
