use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract SchemaArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 schema;
        }
    }
}

crate::impl_encode_and_decode!(
    SchemaArbiterComposing,
    encode_schema_arbiter_composing_demand,
    decode_schema_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    SchemaArbiterComposingApi,
    SchemaArbiterComposing::DemandData,
    encode_schema_arbiter_composing_demand,
    decode_schema_arbiter_composing_demand
);
