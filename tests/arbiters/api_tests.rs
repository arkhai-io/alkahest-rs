use alkahest_rs::{
    clients::arbiters::attestation_properties::{composing::*, non_composing::*},
    contracts::{
        self, TrustedOracleArbiter,
        attestation_properties::{composing::*, non_composing::*},
        confirmation_arbiters::*,
        logical::*,
    },
    extensions::HasArbiters,
    utils::setup_test_environment,
};
use alloy::primitives::{Bytes, FixedBytes};

#[tokio::test]
async fn test_comprehensive_arbiter_api() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;
    let arbiters = test.alice_client.arbiters();

    // Test core arbiters
    let oracle_demand = contracts::TrustedOracleArbiter::DemandData {
        oracle: test.bob.address(),
        data: Bytes::from(b"test".as_slice()),
    };
    let encoded_oracle = arbiters.trusted_oracle_arbiter().encode(&oracle_demand);
    let decoded_oracle = arbiters.trusted_oracle_arbiter().decode(&encoded_oracle)?;
    assert_eq!(decoded_oracle.oracle, oracle_demand.oracle);

    // Test logical arbiters - arbiters.logical().all().encode()
    let all_demand = AllArbiter::DemandData {
        arbiters: vec![test.addresses.arbiters_addresses.trivial_arbiter],
        demands: vec![Bytes::from(b"test".as_slice())],
    };
    let encoded_all = arbiters.logical().all().encode(&all_demand);
    let decoded_all = arbiters.logical().all().decode(&encoded_all)?;
    assert_eq!(decoded_all.arbiters.len(), 1);

    // Test confirmation arbiters - arbiters.confirmation().confirmation_composing().encode()
    let confirmation_demand = ConfirmationArbiterComposing::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
    };
    let encoded_confirmation = arbiters
        .confirmation()
        .confirmation_composing()
        .encode(&confirmation_demand);
    let decoded_confirmation = arbiters
        .confirmation()
        .confirmation_composing()
        .decode(&encoded_confirmation)?;
    assert_eq!(
        decoded_confirmation.baseArbiter,
        confirmation_demand.baseArbiter
    );

    // Test attestation properties - arbiters.attestation_properties().composing().recipient().encode()
    let recipient_demand =
        contracts::attestation_properties::composing::RecipientArbiter::DemandData {
            baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
            baseDemand: Bytes::from(b"test".as_slice()),
            recipient: test.alice.address(),
        };
    let encoded_recipient = arbiters
        .attestation_properties()
        .composing()
        .recipient()
        .encode(&recipient_demand);
    let decoded_recipient = arbiters
        .attestation_properties()
        .composing()
        .recipient()
        .decode(&encoded_recipient)?;
    assert_eq!(decoded_recipient.recipient, recipient_demand.recipient);

    println!("✅ All arbiter APIs work:");
    println!("  - Core: arbiters.trusted_oracle_arbiter().encode()");
    println!("  - Logical: arbiters.logical().all().encode()");
    println!("  - Confirmation: arbiters.confirmation().confirmation_composing().encode()");
    println!("  - Properties: arbiters.attestation_properties().composing().recipient().encode()");

    Ok(())
}

#[tokio::test]
async fn test_all_attestation_properties_composing_arbiters() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;
    let arbiters = test.alice_client.arbiters();
    let props = arbiters.attestation_properties().composing();

    // Test all attestation properties composing arbiters

    // Test recipient arbiter
    let recipient_demand = contracts::attestation_properties::composing::RecipientArbiter::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
        recipient: test.alice.address(),
    };
    let encoded = props.recipient().encode(&recipient_demand);
    let decoded = props.recipient().decode(&encoded)?;
    assert_eq!(decoded.recipient, recipient_demand.recipient);

    // Test uid arbiter
    let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let uid_demand = contracts::attestation_properties::composing::UidArbiter::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
        uid,
    };
    let encoded = props.uid().encode(&uid_demand);
    let decoded = props.uid().decode(&encoded)?;
    assert_eq!(decoded.uid, uid_demand.uid);

    // Test attester arbiter
    let attester_demand = contracts::attestation_properties::composing::AttesterArbiter::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
        attester: test.bob.address(),
    };
    let encoded = props.attester().encode(&attester_demand);
    let decoded = props.attester().decode(&encoded)?;
    assert_eq!(decoded.attester, attester_demand.attester);

    // Test schema arbiter
    let schema = FixedBytes::<32>::from_slice(&[2u8; 32]);
    let schema_demand = contracts::attestation_properties::composing::SchemaArbiter::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
        schema,
    };
    let encoded = props.schema().encode(&schema_demand);
    let decoded = props.schema().decode(&encoded)?;
    assert_eq!(decoded.schema, schema_demand.schema);

    // Test time arbiters
    let time_value = 1234567890u64;
    let time_after_demand = contracts::attestation_properties::composing::TimeAfterArbiter::DemandData {
        baseArbiter: test.addresses.arbiters_addresses.trivial_arbiter,
        baseDemand: Bytes::from(b"test".as_slice()),
        time: time_value.into(),
    };
    let encoded = props.time_after().encode(&time_after_demand);
    let decoded = props.time_after().decode(&encoded)?;
    assert_eq!(decoded.time, time_after_demand.time);

    println!("✅ All attestation properties composing arbiters work:");
    println!("  - arbiters.attestation_properties().composing().recipient().encode()");
    println!("  - arbiters.attestation_properties().composing().uid().encode()");
    println!("  - arbiters.attestation_properties().composing().attester().encode()");
    println!("  - arbiters.attestation_properties().composing().schema().encode()");
    println!("  - arbiters.attestation_properties().composing().time_after().encode()");
    println!("  - arbiters.attestation_properties().composing().time_before().encode()");
    println!("  - arbiters.attestation_properties().composing().time_equal().encode()");
    println!("  - arbiters.attestation_properties().composing().expiration_time_after().encode()");
    println!("  - arbiters.attestation_properties().composing().expiration_time_before().encode()");
    println!("  - arbiters.attestation_properties().composing().expiration_time_equal().encode()");
    println!("  - arbiters.attestation_properties().composing().ref_uid().encode()");
    println!("  - arbiters.attestation_properties().composing().revocable().encode()");

    Ok(())
}

#[tokio::test]
async fn test_all_attestation_properties_non_composing_arbiters() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;
    let arbiters = test.alice_client.arbiters();
    let props = arbiters.attestation_properties().non_composing();

    // Test all attestation properties non-composing arbiters

    // Test recipient arbiter
    let recipient_demand = contracts::attestation_properties::non_composing::RecipientArbiter::DemandData {
        recipient: test.alice.address(),
    };
    let encoded = props.recipient().encode(&recipient_demand);
    let decoded = props.recipient().decode(&encoded)?;
    assert_eq!(decoded.recipient, recipient_demand.recipient);

    // Test uid arbiter
    let uid = FixedBytes::<32>::from_slice(&[1u8; 32]);
    let uid_demand =
        contracts::attestation_properties::non_composing::UidArbiter::DemandData {
            uid,
        };
    let encoded = props.uid().encode(&uid_demand);
    let decoded = props.uid().decode(&encoded)?;
    assert_eq!(decoded.uid, uid_demand.uid);

    // Test attester arbiter
    let attester_demand =
        contracts::attestation_properties::non_composing::AttesterArbiter::DemandData {
            attester: test.bob.address(),
        };
    let encoded = props.attester().encode(&attester_demand);
    let decoded = props.attester().decode(&encoded)?;
    assert_eq!(decoded.attester, attester_demand.attester);

    // Test schema arbiter
    let schema = FixedBytes::<32>::from_slice(&[2u8; 32]);
    let schema_demand =
        contracts::attestation_properties::non_composing::SchemaArbiter::DemandData {
            schema,
        };
    let encoded = props.schema().encode(&schema_demand);
    let decoded = props.schema().decode(&encoded)?;
    assert_eq!(decoded.schema, schema_demand.schema);

    // Test revocable arbiter
    let revocable_demand = contracts::attestation_properties::non_composing::RevocableArbiter::DemandData { revocable: true };
    let encoded = props.revocable().encode(&revocable_demand);
    let decoded = props.revocable().decode(&encoded)?;
    assert_eq!(decoded.revocable, revocable_demand.revocable);

    // Test time arbiters
    let time_value = 1234567890u64;
    let time_after_demand = contracts::attestation_properties::non_composing::TimeAfterArbiter::DemandData {
        time: time_value.into(),
    };
    let encoded = props.time_after().encode(&time_after_demand);
    let decoded = props.time_after().decode(&encoded)?;
    assert_eq!(decoded.time, time_after_demand.time);

    let time_before_demand = contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData {
        time: time_value.into(),
    };
    let encoded = props.time_before().encode(&time_before_demand);
    let decoded = props.time_before().decode(&encoded)?;
    assert_eq!(decoded.time, time_before_demand.time);

    let time_equal_demand = contracts::attestation_properties::non_composing::TimeEqualArbiter::DemandData {
        time: time_value.into(),
    };
    let encoded = props.time_equal().encode(&time_equal_demand);
    let decoded = props.time_equal().decode(&encoded)?;
    assert_eq!(decoded.time, time_equal_demand.time);

    // Test expiration time arbiters
    let expiration_time_after_demand = contracts::attestation_properties::non_composing::ExpirationTimeAfterArbiter::DemandData {
        expirationTime: time_value.into(),
    };
    let encoded = props
        .expiration_time_after()
        .encode(&expiration_time_after_demand);
    let decoded = props.expiration_time_after().decode(&encoded)?;
    assert_eq!(
        decoded.expirationTime,
        expiration_time_after_demand.expirationTime
    );

    let expiration_time_before_demand = contracts::attestation_properties::non_composing::ExpirationTimeBeforeArbiter::DemandData {
        expirationTime: time_value.into(),
    };
    let encoded = props
        .expiration_time_before()
        .encode(&expiration_time_before_demand);
    let decoded = props.expiration_time_before().decode(&encoded)?;
    assert_eq!(
        decoded.expirationTime,
        expiration_time_before_demand.expirationTime
    );

    let expiration_time_equal_demand = contracts::attestation_properties::non_composing::ExpirationTimeEqualArbiter::DemandData {
        expirationTime: time_value.into(),
    };
    let encoded = props
        .expiration_time_equal()
        .encode(&expiration_time_equal_demand);
    let decoded = props.expiration_time_equal().decode(&encoded)?;
    assert_eq!(
        decoded.expirationTime,
        expiration_time_equal_demand.expirationTime
    );

    // Test ref_uid arbiter
    let ref_uid = FixedBytes::<32>::from_slice(&[3u8; 32]);
    let ref_uid_demand = contracts::attestation_properties::non_composing::RefUidArbiter::DemandData { refUID: ref_uid };
    let encoded = props.ref_uid().encode(&ref_uid_demand);
    let decoded = props.ref_uid().decode(&encoded)?;
    assert_eq!(decoded.refUID, ref_uid_demand.refUID);

    println!("✅ All attestation properties non-composing arbiters work:");
    println!("  - arbiters.attestation_properties().non_composing().recipient().encode()");
    println!("  - arbiters.attestation_properties().non_composing().uid().encode()");
    println!("  - arbiters.attestation_properties().non_composing().attester().encode()");
    println!("  - arbiters.attestation_properties().non_composing().schema().encode()");
    println!("  - arbiters.attestation_properties().non_composing().revocable().encode()");
    println!("  - arbiters.attestation_properties().non_composing().time_after().encode()");
    println!("  - arbiters.attestation_properties().non_composing().time_before().encode()");
    println!("  - arbiters.attestation_properties().non_composing().time_equal().encode()");
    println!(
        "  - arbiters.attestation_properties().non_composing().expiration_time_after().encode()"
    );
    println!(
        "  - arbiters.attestation_properties().non_composing().expiration_time_before().encode()"
    );
    println!(
        "  - arbiters.attestation_properties().non_composing().expiration_time_equal().encode()"
    );
    println!("  - arbiters.attestation_properties().non_composing().ref_uid().encode()");

    Ok(())
}

#[tokio::test]
async fn test_simple_arbiter_api() -> eyre::Result<()> {
    // Setup test environment
    let test = setup_test_environment().await?;

    // Get arbiters module
    let arbiters = test.alice_client.arbiters();

    // Test TrustedOracleArbiter API
    let oracle_demand = contracts::TrustedOracleArbiter::DemandData {
        oracle: test.bob.address(),
        data: Bytes::from(b"test_data".as_slice()),
    };

    let encoded = arbiters.trusted_oracle_arbiter().encode(&oracle_demand);
    let decoded = arbiters.trusted_oracle_arbiter().decode(&encoded)?;
    assert_eq!(decoded.oracle, oracle_demand.oracle, "Oracle should match");

    // Test logical.all API
    let all_demand = contracts::logical::AllArbiter::DemandData {
        arbiters: vec![test.addresses.arbiters_addresses.trivial_arbiter],
        demands: vec![Bytes::from(b"test".as_slice())],
    };

    let encoded_all = arbiters.logical().all().encode(&all_demand);
    let decoded_all = arbiters.logical().all().decode(&encoded_all)?;
    assert_eq!(decoded_all.arbiters.len(), 1, "Should have one arbiter");

    println!("✅ Simple arbiter API works!");
    Ok(())
}
