use crate::clients::arbiters::ArbitersModule;
use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract SchemaArbiterNonComposing {
        struct DemandData {
            bytes32 schema;
        }
    }
}

impl_encode_and_decode!(
    SchemaArbiterNonComposing,
    encode_schema_arbiter_non_composing_demand,
    decode_schema_arbiter_non_composing_demand
);

crate::impl_arbiter_api!(
    SchemaArbiterNonComposingApi,
    SchemaArbiterNonComposing::DemandData,
    encode_schema_arbiter_non_composing_demand,
    decode_schema_arbiter_non_composing_demand
);
