use crate::{
    clients::arbiters::ArbitersModule,
    contracts::confirmation_arbiters::UnrevocableConfirmationArbiterComposing::DemandData,
    impl_arbiter_api, impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_unrevocable_confirmation_arbiter_composing_demand,
    decode_unrevocable_confirmation_arbiter_composing_demand
);
impl_arbiter_api!(
    UnrevocableConfirmationArbiterComposing,
    DemandData,
    encode_unrevocable_confirmation_arbiter_composing_demand,
    decode_unrevocable_confirmation_arbiter_composing_demand,
    unrevocable_confirmation_arbiter_composing
);
