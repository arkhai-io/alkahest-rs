use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::UidArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_uid_arbiter_non_composing_demand,
    decode_uid_arbiter_non_composing_demand
);
impl_arbiter_api!(
    UidArbiterNonComposing,
    DemandData,
    encode_uid_arbiter_non_composing_demand,
    decode_uid_arbiter_non_composing_demand,
    uid_arbiter_non_composing
);
