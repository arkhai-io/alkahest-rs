use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::ExpirationTimeBeforeArbiter::DemandData,
    impl_arbiter_api, impl_encode_and_decode,
};

impl From<DemandData> for alloy::primitives::Bytes {
    fn from(demand: DemandData) -> Self {
        use alloy::sol_types::SolValue as _;
        demand.abi_encode().into()
    }
}

impl TryFrom<&alloy::primitives::Bytes> for DemandData {
    type Error = eyre::Error;

    fn try_from(data: &alloy::primitives::Bytes) -> Result<Self, Self::Error> {
        use alloy::sol_types::SolValue as _;
        Ok(Self::abi_decode(data)?)
    }
}

impl TryFrom<alloy::primitives::Bytes> for DemandData {
    type Error = eyre::Error;

    fn try_from(data: alloy::primitives::Bytes) -> Result<Self, Self::Error> {
        use alloy::sol_types::SolValue as _;
        Ok(Self::abi_decode(&data)?)
    }
}

impl_encode_and_decode!(
    DemandData,
    encode_expiration_time_before_arbiter_composing_demand,
    decode_expiration_time_before_arbiter_composing_demand
);
impl_arbiter_api!(
    ExpirationTimeBeforeArbiterComposing,
    DemandData,
    encode_expiration_time_before_arbiter_composing_demand,
    decode_expiration_time_before_arbiter_composing_demand,
    expiration_time_before_arbiter_composing
);
