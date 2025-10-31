use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::non_composing::ExpirationTimeBeforeArbiter::DemandData,
    impl_arbiter_api, impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_expiration_time_before_arbiter_non_composing_demand,
    decode_expiration_time_before_arbiter_non_composing_demand
);
impl_arbiter_api!(
    ExpirationTimeBeforeArbiterNonComposing,
    DemandData,
    encode_expiration_time_before_arbiter_non_composing_demand,
    decode_expiration_time_before_arbiter_non_composing_demand,
    expiration_time_before_arbiter_non_composing
);
