#![cfg(feature = "circuit_input_builder")]

use bus_mapping::circuit_input_builder::{gen_state_access_trace, AccessSet};
use bus_mapping::eth_types::Word;
use integration_tests::{get_client, GenDataOutput};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

#[tokio::test]
async fn test_one() {
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

    for access in &access_trace {
        println!("{:#?}", access);
    }

    let access_set = AccessSet::from(access_trace);
    println!("{:#?}", access_set);

    for (address, key_set) in access_set.state {
        let mut keys: Vec<Word> = key_set.iter().cloned().collect();
        keys.sort();
        let proof = cli
            .get_proof(address, keys, (*block_num - 1).into())
            .await
            .unwrap();
        println!("proof for {:?}:\n{:#?}", address, proof);
    }
}
