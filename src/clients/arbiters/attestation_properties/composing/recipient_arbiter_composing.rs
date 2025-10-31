use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::composing::RecipientArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_recipient_arbiter_composing_demand,
    decode_recipient_arbiter_composing_demand
);
impl_arbiter_api!(
    RecipientArbiterComposing,
    DemandData,
    encode_recipient_arbiter_composing_demand,
    decode_recipient_arbiter_composing_demand,
    recipient_arbiter_composing
);
