use crate::{clients::arbiters::ArbitersModule, contracts::SpecificAttestationArbiter::DemandData, impl_encode_and_decode, impl_arbiter_api};

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
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand
);
impl_arbiter_api!(
    SpecificAttestationArbiter,
    DemandData,
    encode_specific_attestation_arbiter_demand,
    decode_specific_attestation_arbiter_demand,
    specific_attestation_arbiter
);
