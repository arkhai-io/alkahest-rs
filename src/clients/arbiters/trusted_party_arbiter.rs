use crate::{clients::arbiters::ArbitersModule, impl_arbiter_api, impl_encode_and_decode};
use alloy::sol;

sol! {
    contract TrustedPartyArbiter {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address creator;
        }
    }
}

impl_encode_and_decode!(
    TrustedPartyArbiter,
    encode_trusted_party_arbiter_demand,
    decode_trusted_party_arbiter_demand
);

impl_arbiter_api!(
    TrustedPartyArbiterApi,
    TrustedPartyArbiter::DemandData,
    encode_trusted_party_arbiter_demand,
    decode_trusted_party_arbiter_demand
);
