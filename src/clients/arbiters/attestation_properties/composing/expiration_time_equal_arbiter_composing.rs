use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract ExpirationTimeEqualArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

crate::impl_encode_and_decode!(
    ExpirationTimeEqualArbiterComposing,
    encode_expiration_time_equal_arbiter_composing_demand,
    decode_expiration_time_equal_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    ExpirationTimeEqualArbiterComposingApi,
    ExpirationTimeEqualArbiterComposing::DemandData,
    encode_expiration_time_equal_arbiter_composing_demand,
    decode_expiration_time_equal_arbiter_composing_demand
);
