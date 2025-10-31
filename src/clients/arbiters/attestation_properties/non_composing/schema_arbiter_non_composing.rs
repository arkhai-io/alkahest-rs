use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::SchemaArbiter::DemandData, impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_schema_arbiter_non_composing_demand,
    decode_schema_arbiter_non_composing_demand
);
impl_arbiter_api!(
    SchemaArbiterNonComposing,
    DemandData,
    encode_schema_arbiter_non_composing_demand,
    decode_schema_arbiter_non_composing_demand,
    schema_arbiter_non_composing
);
