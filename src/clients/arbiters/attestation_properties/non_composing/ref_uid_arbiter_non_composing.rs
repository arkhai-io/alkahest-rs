use crate::{clients::arbiters::ArbitersModule, 
    contracts::ref_uid_arbiters::non_composing::RefUidArbiter::DemandData, impl_encode_and_decode, impl_arbiter_api
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
