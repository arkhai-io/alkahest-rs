use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::RecipientArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_recipient_arbiter_non_composing_demand,
    decode_recipient_arbiter_non_composing_demand
);
impl_arbiter_api!(
    RecipientArbiterNonComposing,
    DemandData,
    encode_recipient_arbiter_non_composing_demand,
    decode_recipient_arbiter_non_composing_demand,
    recipient_arbiter_non_composing
);
