use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract UidArbiterNonComposing {
        struct DemandData {
            bytes32 uid;
        }
    }
}

impl_encode_and_decode!(
    UidArbiterNonComposing,
    encode_uid_arbiter_non_composing_demand,
    decode_uid_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    UidArbiterNonComposingApi,
    UidArbiterNonComposing::DemandData,
    encode_uid_arbiter_non_composing_demand,
    decode_uid_arbiter_non_composing_demand
);
