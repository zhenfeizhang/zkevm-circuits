#![cfg(feature = "circuit_input_builder")]

use bus_mapping::circuit_input_builder::{
    gen_state_access_trace, AccessSet, CircuitInputBuilder,
};
use bus_mapping::eth_types::{Word, H256};
use bus_mapping::state_db;
use ethers::core::utils::keccak256;
use integration_tests::{get_chain_constants, get_client, GenDataOutput};
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

/// This test builds the complete circuit inputs for the block where the Greeter
/// contract is deployed.
#[tokio::test]
async fn test_circuit_input_builder_block_a() {
    let (block_num, _address) = GEN_DATA.deployments.get("Greeter").unwrap();

    let cli = get_client();
    let eth_block = cli.get_block_by_number((*block_num).into()).await.unwrap();
    let geth_trace = cli
        .trace_block_by_number((*block_num).into())
        .await
        .unwrap();
    let tx_index = 0;

    let access_trace = gen_state_access_trace(
        &eth_block,
        &eth_block.transactions[tx_index],
        &geth_trace[tx_index],
    )
    .unwrap();

    // for access in &access_trace {
    //     println!("{:#?}", access);
    // }

    let access_set = AccessSet::from(access_trace);
    println!("AccessSet: {:#?}", access_set);

    let mut proofs = Vec::new();
    for (address, key_set) in access_set.state {
        let mut keys: Vec<Word> = key_set.iter().cloned().collect();
        keys.sort();
        let proof = cli
            .get_proof(address, keys, (*block_num - 1).into())
            .await
            .unwrap();
        proofs.push(proof);
        // println!("proof for {:?}:\n{:#?}", address, proof);
    }
    let mut codes = HashMap::new();
    for address in access_set.code {
        let code = cli
            .get_code(address, (*block_num - 1).into())
            .await
            .unwrap();
        codes.insert(address.clone(), code);
    }

    let constants = get_chain_constants().await;
    let mut builder = CircuitInputBuilder::new(&eth_block, constants);

    for proof in proofs {
        let mut storage = HashMap::new();
        for storage_proof in proof.storage_proof {
            storage.insert(storage_proof.key, storage_proof.value);
        }
        builder.sdb.set_account(
            &proof.address,
            state_db::Account {
                nonce: proof.nonce,
                balance: proof.balance,
                storage,
                code_hash: proof.code_hash,
            },
        )
    }
    // println!("StateDB: {:#?}", builder.sdb);

    for (address, code) in codes {
        let hash = H256(keccak256(&code));
        builder.codes.insert(hash, code.clone());
    }

    let block_geth_trace = cli
        .trace_block_by_number((*block_num).into())
        .await
        .unwrap();
    for tx_index in 0..eth_block.transactions.len() {
        let tx = &eth_block.transactions[tx_index];
        let geth_trace = &block_geth_trace[tx_index];
        builder.handle_tx(tx, geth_trace).unwrap();
    }

    println!("CircuitInputBuilder: {:#?}", builder);
}
