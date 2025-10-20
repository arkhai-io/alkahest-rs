use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract TimeEqualArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

crate::impl_encode_and_decode!(
    TimeEqualArbiterComposing,
    encode_time_equal_arbiter_composing_demand,
    decode_time_equal_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    TimeEqualArbiterComposingApi,
    TimeEqualArbiterComposing::DemandData,
    encode_time_equal_arbiter_composing_demand,
    decode_time_equal_arbiter_composing_demand
);
