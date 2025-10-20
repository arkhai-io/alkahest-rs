use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract TimeBeforeArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

impl_encode_and_decode!(
    TimeBeforeArbiterNonComposing,
    encode_time_before_arbiter_non_composing_demand,
    decode_time_before_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    TimeBeforeArbiterNonComposingApi,
    TimeBeforeArbiterNonComposing::DemandData,
    encode_time_before_arbiter_non_composing_demand,
    decode_time_before_arbiter_non_composing_demand
);
