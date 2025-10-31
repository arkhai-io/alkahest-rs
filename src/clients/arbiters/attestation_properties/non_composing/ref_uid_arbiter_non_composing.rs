use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::RefUidArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_ref_uid_arbiter_non_composing_demand,
    decode_ref_uid_arbiter_non_composing_demand
);
impl_arbiter_api!(
    RefUidArbiterNonComposing,
    DemandData,
    encode_ref_uid_arbiter_non_composing_demand,
    decode_ref_uid_arbiter_non_composing_demand,
    ref_uid_arbiter_non_composing
);
