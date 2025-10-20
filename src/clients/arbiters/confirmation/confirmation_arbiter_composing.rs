use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract ConfirmationArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

crate::impl_encode_and_decode!(
    ConfirmationArbiterComposing,
    encode_confirmation_arbiter_composing_demand,
    decode_confirmation_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    ConfirmationArbiterComposingApi,
    ConfirmationArbiterComposing::DemandData,
    encode_confirmation_arbiter_composing_demand,
    decode_confirmation_arbiter_composing_demand
);
