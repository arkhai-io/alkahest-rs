use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract RevocableArbiterNonComposing {
        struct DemandData {
            bool revocable;
        }
    }
}

impl_encode_and_decode!(
    RevocableArbiterNonComposing,
    encode_revocable_arbiter_non_composing_demand,
    decode_revocable_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    RevocableArbiterNonComposingApi,
    RevocableArbiterNonComposing::DemandData,
    encode_revocable_arbiter_non_composing_demand,
    decode_revocable_arbiter_non_composing_demand
);
