use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract TimeAfterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

crate::impl_encode_and_decode!(
    TimeAfterArbiterComposing,
    encode_time_after_arbiter_composing_demand,
    decode_time_after_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    TimeAfterArbiterComposingApi,
    TimeAfterArbiterComposing::DemandData,
    encode_time_after_arbiter_composing_demand,
    decode_time_after_arbiter_composing_demand
);
