//! Mock types and functions to generate GethData used for tests

use eth_types::{
    address,
    bytecode::Bytecode,
    evm_types::Gas,
    geth_types::{Account, BlockConstants, GethData, Transaction},
    Address, Block, Bytes, Error, Hash, Word, U64,
};
use external_tracer::{trace, TraceConfig};
use lazy_static::lazy_static;
mod account;
mod block;
mod test_ctx;
mod trace;
mod transaction;

pub use account::MockAccount;
pub use block::MockBlock;
pub use test_ctx::TestContext;
pub use trace::MockTrace;
pub use transaction::MockTransaction;

lazy_static! {
    /// Mock coinbase value
    static ref MOCK_COINBASE: Address =
        address!("0x00000000000000000000000000000000c014ba5e");
    /// Mock gasprice value
    static ref MOCK_GASPRICE: Word = Word::from(1u8);
    /// Mock chain ID value
    static ref MOCK_CHAIN_ID: Word = Word::from(1338u64);
    /// Mock accounts loaded with ETH to use for test cases.
    static ref MOCK_ACCOUNTS: Vec<Address> = vec![
        address!("0x0000000000000000000000000000000000000111"),
        address!("0x0000000000000000000000000000000000000222"),
        address!("0x0000000000000000000000000000000000000333"),
        address!("0x0000000000000000000000000000000000000444"),
        address!("0x0000000000000000000000000000000000000555"),
    ];
}

/// Create a new block with a single tx that executes the code found in the
/// account with address 0x0 (which can call code in the other accounts),
/// with the given gas limit.
/// The trace will be generated automatically with the external_tracer
/// from the accounts code.
pub fn new_single_tx_trace_accounts_gas(
    accounts: Vec<Account>,
    gas: Gas,
) -> Result<GethData, Error> {
    // let eth_block = new_block();
    // let mut eth_tx = new_tx(&eth_block);
    // eth_tx.gas = Word::from(gas.0);

    // let trace_config = TraceConfig {
    //     chain_id: *MOCK_CHAIN_ID,
    //     // TODO: Add mocking history_hashes when nedded.
    //     history_hashes: Vec::new(),
    //     block_constants: BlockConstants::try_from(&eth_block)?,
    //     accounts: accounts
    //         .iter()
    //         .map(|account| (account.address, account.clone()))
    //         .collect(),
    //     transaction: Transaction::from_eth_tx(&eth_tx),
    // };
    // let geth_trace = trace(&trace_config)?;

    // Ok(GethData {
    //     chain_id: trace_config.chain_id,
    //     history_hashes: trace_config.history_hashes,
    //     eth_block,
    //     eth_tx,
    //     geth_trace,
    //     accounts,
    // })
    unimplemented!()
}

/// Create a new block with a single tx that executes the code found in the
/// account with address 0x0 (which can call code in the other accounts).
/// The trace will be generated automatically with the external_tracer
/// from the accounts code.
pub fn new_single_tx_trace_accounts(accounts: Vec<Account>) -> Result<GethData, Error> {
    //new_single_tx_trace_accounts_gas(accounts, Gas(1_000_000u64))
    unimplemented!()
}

/// Create a new block with a single tx that executes the code passed by
/// argument.  The trace will be generated automatically with the
/// external_tracer from the code.
pub fn new_single_tx_trace_code(code: &Bytecode) -> Result<GethData, Error> {
    // let tracer_account = new_tracer_account(code);
    // new_single_tx_trace_accounts(vec![tracer_account])
    unimplemented!()
}

/// Create a new block with a single tx with the given gas limit that
/// executes the code passed by argument.  The trace will be generated
/// automatically with the external_tracer from the code.
pub fn new_single_tx_trace_code_gas(code: &Bytecode, gas: Gas) -> Result<GethData, Error> {
    // let tracer_account = new_tracer_account(code);
    // new_single_tx_trace_accounts_gas(vec![tracer_account], gas)
    unimplemented!()
}

/// Create a new block with a single tx that executes the code_a passed by
/// argument, with code_b deployed at address 0x123.  The trace will be
/// generated automatically with the external_tracer from the code.
pub fn new_single_tx_trace_code_2(code_a: &Bytecode, code_b: &Bytecode) -> Result<GethData, Error> {
    // let tracer_account_a = new_tracer_account(code_a);
    // let mut tracer_account_b = new_tracer_account(code_b);
    // tracer_account_b.address =
    // address!("0x0000000000000000000000000000000000000123");
    // new_single_tx_trace_accounts(vec![tracer_account_a, tracer_account_b])
    unimplemented!()
}

/// Create a new block with a single tx that executes the code passed by
/// argument.  The trace will be generated automatically with the
/// external_tracer from the code.  The trace steps will start at the
/// "start" position as tagged in the code.
pub fn new_single_tx_trace_code_at_start(code: &Bytecode) -> Result<GethData, Error> {
    // let mut geth_data = new_single_tx_trace_code(code)?;
    // geth_data.geth_trace.struct_logs =
    //     geth_data.geth_trace.struct_logs[code.get_pos("start")..].to_vec();
    // Ok(geth_data)
    unimplemented!()
}
