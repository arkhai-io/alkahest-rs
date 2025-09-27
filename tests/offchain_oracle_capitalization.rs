use std::{
    convert::TryInto,
    marker::PhantomData,
    process::Command,
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use alkahest_rs::{
    AlkahestClient, DefaultAlkahestClient,
    clients::{
        arbiters::{ArbitersModule, TrustedOracleArbiter},
        oracle::{ArbitrateOptions, AttestationFilter, EscrowParams, FulfillmentParams},
    },
    contracts::StringObligation,
    extensions::{HasErc20, HasOracle, HasStringObligation},
    fixtures::MockERC20Permit,
    types::{ArbiterData, Erc20Data},
    utils::{TestContext, setup_test_environment},
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Bytes,
    rpc::types::{FilterBlockOption, ValueOrArray},
    signers::local::PrivateKeySigner,
};
use eyre::{Result, WrapErr, eyre};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ShellTestCase {
    input: String,
    output: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ShellOracleDemand {
    description: String,
    test_cases: Vec<ShellTestCase>,
}

async fn run_synchronous_oracle_capitalization_example(test: &TestContext) -> eyre::Result<()> {
    // Charlie is the off-chain oracle Alice requests in her escrow demand.
    let charlie_signer: PrivateKeySigner = test.anvil.keys()[3].clone().into();
    let charlie_client = AlkahestClient::with_base_extensions(
        charlie_signer.clone(),
        test.anvil.ws_endpoint_url(),
        Some(test.addresses.clone()),
    )
    .await
    .wrap_err("failed to construct Charlie's client")?;
    let charlie_oracle = charlie_client.oracle().clone();

    // Step 1. Alice escrows ERC20 collateral guarded by Charlie's oracle suite.
    let mock_erc20 = MockERC20Permit::new(test.mock_addresses.erc20_a, &test.god_provider);
    mock_erc20
        .transfer(test.alice.address(), 100u64.try_into()?)
        .send()
        .await?
        .get_receipt()
        .await?;

    let demand_payload = ShellOracleDemand {
        description: "Capitalize stdin".to_owned(),
        test_cases: vec![
            ShellTestCase {
                input: "alice".to_owned(),
                output: "ALICE".to_owned(),
            },
            ShellTestCase {
                input: "bob builder".to_owned(),
                output: "BOB BUILDER".to_owned(),
            },
        ],
    };

    let encoded_demand =
        ArbitersModule::encode_trusted_oracle_arbiter_demand(&TrustedOracleArbiter::DemandData {
            oracle: charlie_client.address,
            data: Bytes::from(
                serde_json::to_vec(&demand_payload)
                    .wrap_err("failed to encode oracle demand payload")?,
            ),
        });

    let arbiter_item = ArbiterData {
        arbiter: test.addresses.arbiters_addresses.trusted_oracle_arbiter,
        demand: encoded_demand,
    };

    let price = Erc20Data {
        address: test.mock_addresses.erc20_a,
        value: 100u64.try_into()?,
    };

    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .checked_add(StdDuration::from_secs(3600))
        .ok_or_else(|| eyre!("expiration overflow"))?
        .as_secs();

    let escrow_receipt = test
        .alice_client
        .erc20()
        .permit_and_buy_with_erc20(&price, &arbiter_item, expiration)
        .await?;
    let escrow_uid = DefaultAlkahestClient::get_attested_event(escrow_receipt)?.uid;

    // Step 2. Bob submits a bash pipeline fulfillment.
    let fulfillment_receipt = test
        .bob_client
        .string_obligation()
        .do_obligation("tr '[:lower:]' '[:upper:]'".to_owned(), Some(escrow_uid))
        .await?;
    let fulfillment_uid = DefaultAlkahestClient::get_attested_event(fulfillment_receipt)?.uid;

    // Step 3. Bob asks Charlie to arbitrate his fulfillment.
    test.bob_client
        .oracle()
        .request_arbitration(fulfillment_uid, charlie_client.address)
        .await?;

    // Step 4. Charlie evaluates the backlog and watches for new fulfillments.
    let fulfillment = FulfillmentParams::<StringObligation::ObligationData> {
        filter: AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses.string_obligation_addresses.obligation,
            )),
            recipient: Some(ValueOrArray::Value(test.bob.address())),
            schema_uid: None,
            uid: None,
            ref_uid: Some(ValueOrArray::Value(escrow_uid)),
            block_option: Some(FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Earliest),
                to_block: Some(BlockNumberOrTag::Latest),
            }),
        },
        _obligation_data: PhantomData,
    };

    let escrow = EscrowParams::<TrustedOracleArbiter::DemandData> {
        filter: AttestationFilter {
            attester: Some(ValueOrArray::Value(
                test.addresses.erc20_addresses.escrow_obligation,
            )),
            recipient: Some(ValueOrArray::Value(test.alice.address())),
            schema_uid: None,
            uid: Some(ValueOrArray::Value(escrow_uid)),
            ref_uid: None,
            block_option: Some(FilterBlockOption::Range {
                from_block: Some(BlockNumberOrTag::Earliest),
                to_block: Some(BlockNumberOrTag::Latest),
            }),
        },
        _demand_data: PhantomData,
    };

    let listen_result = charlie_oracle
        .listen_and_arbitrate_for_escrow_sync(
            &escrow,
            &fulfillment,
            |statement, demand| {
                let Ok(payload) = serde_json::from_slice::<ShellOracleDemand>(demand.data.as_ref())
                else {
                    return Some(false);
                };

                for case in payload.test_cases {
                    let command = format!("echo \"$INPUT\" | {}", statement.item);
                    let output = match Command::new("bash")
                        .arg("-lc")
                        .arg(&command)
                        .env("INPUT", &case.input)
                        .output()
                    {
                        Ok(output) if output.status.success() => {
                            String::from_utf8_lossy(&output.stdout)
                                .trim_end()
                                .to_owned()
                        }
                        _ => return Some(false),
                    };

                    if output != case.output {
                        return Some(false);
                    }
                }

                Some(true)
            },
            |_| async {},
            &ArbitrateOptions {
                require_oracle: true,
                skip_arbitrated: true,
                require_request: true,
                only_new: false,
            },
        )
        .await?;

    eyre::ensure!(
        listen_result
            .decisions
            .iter()
            .all(|decision| decision.decision),
        "oracle rejected fulfillment",
    );

    charlie_oracle
        .unsubscribe(listen_result.escrow_subscription_id)
        .await?;
    charlie_oracle
        .unsubscribe(listen_result.fulfillment_subscription_id)
        .await?;

    // Step 5. The successful arbitration lets Bob claim the escrowed payment.
    test.bob_client
        .erc20()
        .collect_escrow(escrow_uid, fulfillment_uid)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_synchronous_offchain_oracle_capitalization_flow() -> Result<()> {
    let test = setup_test_environment().await?;
    run_synchronous_oracle_capitalization_example(&test).await
}
