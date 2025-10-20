use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract AttesterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            address attester;
        }
    }
}

crate::impl_encode_and_decode!(
    AttesterArbiterComposing,
    encode_attester_arbiter_composing_demand,
    decode_attester_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    AttesterArbiterComposingApi,
    AttesterArbiterComposing::DemandData,
    encode_attester_arbiter_composing_demand,
    decode_attester_arbiter_composing_demand
);
