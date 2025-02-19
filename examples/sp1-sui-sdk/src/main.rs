use anyhow::anyhow;
use shared_crypto::intent::Intent;
use sui_config::{SUI_KEYSTORE_FILENAME, sui_config_dir};
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};
use sui_sdk::{
    rpc_types::SuiTransactionBlockResponseOptions,
    types::{
        Identifier,
        base_types::ObjectID,
        programmable_transaction_builder::ProgrammableTransactionBuilder,
        quorum_driver_types::ExecuteTransactionRequestType,
        transaction::{Argument, Command, Transaction, TransactionData},
    },
};

use sp1_sui_sdk::utils::{serialize_input, setup_for_write};
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_sui::convert_sp1_gnark_to_ark;

// Package ID for the Groth16 verifier smart contract deployed on Sui Testnet
const PKG_ID: &str = "0x6bb48e5b05efd5bd07def6569faa50c6c18711ff3aebeb13a9704fe1a1e6076a";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initialize Sui client and get the sender's address and available gas coins
    let (sui, sender, _recipient) = setup_for_write().await?;
    let coins = sui
        .coin_read_api()
        .get_coins(sender, None, None, None)
        .await?;
    let coin = coins.data.into_iter().next().unwrap();

    // Create a new Programmable Transaction Builder for constructing the transaction
    let mut ptb = ProgrammableTransactionBuilder::new();

    // Load the SP1 zero-knowledge proof from file and convert it to Arkworks format
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load("../../proofs/fibonacci_proof.bin").unwrap();
    let (pvk, public_inputs, proof_points) =
        convert_sp1_gnark_to_ark(sp1_proof_with_public_values);

    // Add the proof components as inputs to the transaction
    ptb.input(serialize_input(&pvk))?;           // Input 0: Verification key
    ptb.input(serialize_input(&public_inputs))?;  // Input 1: Public inputs
    ptb.input(serialize_input(&proof_points))?;   // Input 2: Proof points

    // Package and function defined in `examples/move/groth16-verifier`
    let package = ObjectID::from_hex_literal(&PKG_ID).map_err(|e| anyhow!(e))?;
    let module = Identifier::new("groth16_verifier").map_err(|e| anyhow!(e))?;

    ptb.command(Command::move_call(
        package,
        module.clone(),
        Identifier::new("verify_groth16_bn254_proof").map_err(|e| anyhow!(e))?,
        vec![],
        vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
    ));

    // Complete PTB and set gas settings
    let builder = ptb.finish();
    let gas_budget = 10_000_000;
    let gas_price = sui.read_api().get_reference_gas_price().await?;

    let tx_data = TransactionData::new_programmable(
        sender,
        vec![coin.object_ref()],
        builder,
        gas_budget,
        gas_price,
    );

    // Sign and execute the transaction
    let keystore = FileBasedKeystore::new(&sui_config_dir()?.join(SUI_KEYSTORE_FILENAME))?;
    let signature = keystore.sign_secure(&sender, &tx_data, Intent::sui_transaction())?;

    println!("Executing the transaction...");
    let transaction_response = sui
        .quorum_driver_api()
        .execute_transaction_block(
            Transaction::from_data(tx_data, vec![signature]),
            SuiTransactionBlockResponseOptions::full_content(),
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await?;

    println!("{}", transaction_response);

    Ok(())
}
