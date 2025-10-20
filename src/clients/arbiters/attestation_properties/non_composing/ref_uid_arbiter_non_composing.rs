use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract RefUidArbiterNonComposing {
        struct DemandData {
            bytes32 refUID;
        }
    }
}

impl_encode_and_decode!(
    RefUidArbiterNonComposing,
    encode_ref_uid_arbiter_non_composing_demand,
    decode_ref_uid_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    RefUidArbiterNonComposingApi,
    RefUidArbiterNonComposing::DemandData,
    encode_ref_uid_arbiter_non_composing_demand,
    decode_ref_uid_arbiter_non_composing_demand
);
