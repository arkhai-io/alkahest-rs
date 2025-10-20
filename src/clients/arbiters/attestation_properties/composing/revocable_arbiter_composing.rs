use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract RevocableArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bool revocable;
        }
    }
}

crate::impl_encode_and_decode!(
    RevocableArbiterComposing,
    encode_revocable_arbiter_composing_demand,
    decode_revocable_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    RevocableArbiterComposingApi,
    RevocableArbiterComposing::DemandData,
    encode_revocable_arbiter_composing_demand,
    decode_revocable_arbiter_composing_demand
);
