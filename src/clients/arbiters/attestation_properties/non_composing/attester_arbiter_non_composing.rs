use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::AttesterArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_attester_arbiter_non_composing_demand,
    decode_attester_arbiter_non_composing_demand
);
impl_arbiter_api!(
    AttesterArbiterNonComposing,
    DemandData,
    encode_attester_arbiter_non_composing_demand,
    decode_attester_arbiter_non_composing_demand,
    attester_arbiter_non_composing
);
