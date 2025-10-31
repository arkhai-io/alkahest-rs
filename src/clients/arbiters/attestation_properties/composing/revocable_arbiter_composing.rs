use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::RevocableArbiter::DemandData, impl_arbiter_api,
    impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_revocable_arbiter_composing_demand,
    decode_revocable_arbiter_composing_demand
);
impl_arbiter_api!(
    RevocableArbiterComposing,
    DemandData,
    encode_revocable_arbiter_composing_demand,
    decode_revocable_arbiter_composing_demand,
    revocable_arbiter_composing
);
