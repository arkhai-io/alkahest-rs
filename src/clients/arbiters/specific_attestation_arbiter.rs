use crate::{clients::arbiters::ArbitersModule, contracts::SpecificAttestationArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand
);
impl_arbiter_api!(
    SpecificAttestationArbiter,
    DemandData,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand,
    specific_attestation_arbiter
);
