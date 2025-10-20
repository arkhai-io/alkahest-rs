use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract RecipientArbiterNonComposing {
        struct DemandData {
            address recipient;
        }
    }
}

impl_encode_and_decode!(
    RecipientArbiterNonComposing,
    encode_recipient_arbiter_non_composing_demand,
    decode_recipient_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    RecipientArbiterNonComposingApi,
    RecipientArbiterNonComposing::DemandData,
    encode_recipient_arbiter_non_composing_demand,
    decode_recipient_arbiter_non_composing_demand
);
