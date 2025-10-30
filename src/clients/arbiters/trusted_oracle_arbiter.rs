use crate::{
    clients::arbiters::ArbitersModule, contracts::TrustedOracleArbiter::DemandData,
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
    encode_trusted_oracle_arbiter_demand,
    decode_trusted_oracle_arbiter_demand
);

impl_arbiter_api!(
    TrustedOracleArbiter,
    DemandData,
    encode_trusted_oracle_arbiter_demand,
    decode_trusted_oracle_arbiter_demand,
    trusted_oracle_arbiter
);
