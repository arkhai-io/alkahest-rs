use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract UnrevocableConfirmationArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

crate::impl_encode_and_decode!(
    UnrevocableConfirmationArbiterComposing,
    encode_unrevocable_arbiter_composing_demand,
    decode_unrevocable_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    UnrevocableConfirmationArbiterComposingApi,
    UnrevocableConfirmationArbiterComposing::DemandData,
    encode_unrevocable_arbiter_composing_demand,
    decode_unrevocable_arbiter_composing_demand
);
