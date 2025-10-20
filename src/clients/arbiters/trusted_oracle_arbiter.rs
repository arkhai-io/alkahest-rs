use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract TrustedOracleArbiter {
        struct DemandData {
            address oracle;
            bytes data;
        }
    }
}

impl_encode_and_decode!(
    TrustedOracleArbiter,
    encode_trusted_oracle_arbiter_demand,
    decode_trusted_oracle_arbiter_demand
);
