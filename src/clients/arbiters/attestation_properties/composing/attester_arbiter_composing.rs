use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::composing::AttesterArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_attester_arbiter_composing_demand,
    decode_attester_arbiter_composing_demand
);
impl_arbiter_api!(
    AttesterArbiterComposing,
    DemandData,
    encode_attester_arbiter_composing_demand,
    decode_attester_arbiter_composing_demand,
    attester_arbiter_composing
);
