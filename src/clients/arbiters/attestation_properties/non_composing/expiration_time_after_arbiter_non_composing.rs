use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract ExpirationTimeAfterArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

impl_encode_and_decode!(
    ExpirationTimeAfterArbiterNonComposing,
    encode_expiration_time_after_arbiter_non_composing_demand,
    decode_expiration_time_after_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    ExpirationTimeAfterArbiterNonComposingApi,
    ExpirationTimeAfterArbiterNonComposing::DemandData,
    encode_expiration_time_after_arbiter_non_composing_demand,
    decode_expiration_time_after_arbiter_non_composing_demand
);
