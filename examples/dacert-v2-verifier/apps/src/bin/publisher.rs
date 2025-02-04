// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

use alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol_types::{SolCall, SolValue},
};
use alloy_primitives::{Address, U256};
use anyhow::{ensure, Context, Result};
use clap::Parser;
//use dacert_v2_verifier_methods::{BALANCE_OF_ELF, BALANCE_OF_ID};
use dacert_v2_verifier_methods::{DACERT_V2_VERIFIER_ELF, DACERT_V2_VERIFIER_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_HOLESKY_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Commitment, Contract,
};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;
use eigenda_v2_struct_rust::v2_cert;
use std::fs;

use eigenda_v2_struct_rust::v2_cert::sol_struct::{IEigenDACertVerifier};


alloy::sol! {
    struct Journal {
        Commitment commitment;
        address verifierContract;
    }
}


alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/ICounter.sol"
);

/// Simple program to create a proof to increment the Counter contract.
#[derive(Parser)]
struct Args {
    /// Ethereum private key
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum RPC endpoint URL
    #[clap(long, env)]
    eth_rpc_url: Url,

    /// Beacon API endpoint URL
    ///
    /// Steel uses a beacon block commitment instead of the execution block.
    /// This allows proofs to be validated using the EIP-4788 beacon roots contract.
    #[clap(long, env)]
    #[cfg(any(feature = "beacon", feature = "history"))]
    beacon_api_url: Url,

    /// Ethereum block to use as the state for the contract call
    #[clap(long, env, default_value_t = BlockNumberOrTag::Parent)]
    execution_block: BlockNumberOrTag,

    /// Ethereum block to use for the beacon block commitment.
    #[clap(long, env)]
    #[cfg(feature = "history")]
    commitment_block: BlockNumberOrTag,

    /// Address of the Counter verifier contract
    #[clap(long)]
    counter_address: Address,

    /// Address of the EigenDA verifier contract
    /// used to preflight the contract only
    #[clap(long)]
    cert_verifier_contract: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::try_parse()?;

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.eth_rpc_url);

    #[cfg(feature = "beacon")]
    log::info!("Beacon commitment to block {}", args.execution_block);
    #[cfg(feature = "history")]
    log::info!("History commitment to block {}", args.commitment_block);

    let builder = EthEvmEnv::builder()
        .provider(provider.clone())
        .block_number_or_tag(args.execution_block);
    #[cfg(any(feature = "beacon", feature = "history"))]
    let builder = builder.beacon_api(args.beacon_api_url);
    #[cfg(feature = "history")]
    let builder = builder.commitment_block(args.commitment_block);

    let mut env = builder.build().await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_HOLESKY_CHAIN_SPEC);

    let expected_returns = true;

    let batch_header_rlp = fs::read("batch_header.rlp")
        .expect("Should have been able to read the file");
    let non_signer_rlp = fs::read("non_signer.rlp")
        .expect("Should have been able to read the file");
    let blob_inclusion_rlp = fs::read("blob_inclusion.rlp")
        .expect("Should have been able to read the file");
    // given the above abi is correct
    let expected_result_abi = expected_returns.abi_encode();

    let batch_header = v2_cert::parse_batch_header(&batch_header_rlp);
    let non_signer = v2_cert::parse_non_signer(&non_signer_rlp);
    let blob_inclusion = v2_cert::parse_blob_inclusion(&blob_inclusion_rlp);

    let batch_header_abi = batch_header.abi_encode();
    let non_signer_abi = non_signer.abi_encode();
    let blob_inclusion_abi = blob_inclusion.abi_encode();
    
    // Prepare the function call
    let call = IEigenDACertVerifier::verifyDACertV2ForZKProofCall {
        batchHeader: batch_header,
        blobInclusionInfo: blob_inclusion,
        nonSignerStakesAndSignature: non_signer,
    };

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(args.cert_verifier_contract, &mut env);
    let returns = contract.call_builder(&call).call().await?._0;
    assert!(returns == expected_returns);

    // Finally, construct the input from the environment.
    // There are two options: Use EIP-4788 for verification by providing a Beacon API endpoint,
    // or use the regular `blockhash' opcode.
    let evm_input = env.into_input().await?;

    // Create the steel proof.
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&args.cert_verifier_contract)?
            .write(&batch_header_abi)?
            .write(&non_signer_abi)?
            .write(&blob_inclusion_abi)?
            .write(&expected_result_abi)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            DACERT_V2_VERIFIER_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    let receipt = prove_info.receipt;
    let journal = &receipt.journal.bytes;

    // Decode and log the commitment
    let journal = Journal::abi_decode(journal, true).context("invalid journal")?;
    log::debug!("Steel commitment: {:?}", journal.commitment);

    // ABI encode the seal.
    let seal = encode_seal(&receipt).context("invalid receipt")?;

    // Create an alloy instance of the Counter contract.
    let contract = ICounter::new(args.counter_address, &provider);

    // Call ICounter::imageID() to check that the contract has been deployed correctly.
    let contract_image_id = Digest::from(contract.imageID().call().await?._0.0);
    ensure!(contract_image_id == Digest::from(DACERT_V2_VERIFIER_ID));

    // Call the increment function of the contract and wait for confirmation.
    log::info!(
        "Sending Tx calling {} Function of {:#}...",
        ICounter::incrementCall::SIGNATURE,
        contract.address()
    );
    let call_builder = contract.increment(receipt.journal.bytes.into(), seal.into());
    log::debug!("Send {} {}", contract.address(), call_builder.calldata());
    let pending_tx = call_builder.send().await?;
    let tx_hash = *pending_tx.tx_hash();
    let receipt = pending_tx
        .get_receipt()
        .await
        .with_context(|| format!("transaction did not confirm: {}", tx_hash))?;
    ensure!(receipt.status(), "transaction failed: {}", tx_hash);

    Ok(())
}
