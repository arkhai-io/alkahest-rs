use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract IntrinsicsArbiter2 {
        struct DemandData {
            bytes32 schema;
        }
    }
}

impl_encode_and_decode!(
    IntrinsicsArbiter2,
    encode_intrinsics_arbiter2_demand,
    decode_intrinsics_arbiter2_demand
);
