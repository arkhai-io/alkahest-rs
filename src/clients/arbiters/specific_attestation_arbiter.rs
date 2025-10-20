use crate::{clients::arbiters::ArbitersModule, impl_arbiter_api, impl_encode_and_decode};
use alloy::sol;

sol! {
    contract SpecificAttestationArbiter {
        struct DemandData {
            bytes32 uid;
        }
    }
}

impl_encode_and_decode!(
    SpecificAttestationArbiter,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand
);

impl_arbiter_api!(
    SpecificAttestationArbiterApi,
    SpecificAttestationArbiter::DemandData,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand
);
