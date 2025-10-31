use crate::{
    clients::arbiters::ArbitersModule, contracts::TrustedPartyArbiter::DemandData,
    impl_arbiter_api, impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);

impl_encode_and_decode!(
    DemandData,
    encode_trusted_party_arbiter_demand,
    decode_trusted_party_arbiter_demand
);

impl_arbiter_api!(
    TrustedPartyArbiter,
    DemandData,
    encode_trusted_party_arbiter_demand,
    decode_trusted_party_arbiter_demand,
    trusted_party_arbiter
);
