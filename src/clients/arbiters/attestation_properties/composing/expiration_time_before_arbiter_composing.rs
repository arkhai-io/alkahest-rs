use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract ExpirationTimeBeforeArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

crate::impl_encode_and_decode!(
    ExpirationTimeBeforeArbiterComposing,
    encode_expiration_time_before_arbiter_composing_demand,
    decode_expiration_time_before_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    ExpirationTimeBeforeArbiterComposingApi,
    ExpirationTimeBeforeArbiterComposing::DemandData,
    encode_expiration_time_before_arbiter_composing_demand,
    decode_expiration_time_before_arbiter_composing_demand
);
