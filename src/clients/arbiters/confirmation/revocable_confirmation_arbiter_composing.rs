use crate::{clients::arbiters::ArbitersModule, 
    contracts::confirmation_arbiters::RevocableConfirmationArbiterComposing::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_revocable_confirmation_arbiter_composing_demand,
    decode_revocable_confirmation_arbiter_composing_demand
);

impl_arbiter_api!(
    RevocableConfirmationArbiterComposing,
    DemandData,
    encode_revocable_confirmation_arbiter_composing_demand,
    decode_revocable_confirmation_arbiter_composing_demand,
    revocable_confirmation_arbiter_composing
);
