use crate::impl_encode_and_decode;
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
