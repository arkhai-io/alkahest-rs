use crate::{
    clients::arbiters::ArbitersModule, contracts::TrustedOracleArbiter::DemandData,
    impl_arbiter_api, impl_demand_data_conversions, impl_encode_and_decode,
};

impl_demand_data_conversions!(DemandData);

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
