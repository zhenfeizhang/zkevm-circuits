//! Mock types and functions to generate Test enviroments for ZKEVM tests

use crate::{MockAccount, MockBlock, MockTrace, MockTransaction};
use eth_types::{
    geth_types::{Account, BlockConstants, GethData},
    Block, Bytecode, Error, GethExecTrace, Transaction, Word,
};
use external_tracer::{trace, TraceConfig};

/// TestContext is a type that contains all the information from a block
/// required to build the circuit inputs.
#[derive(Debug)]
pub struct TestContext {
    /// chain id
    pub chain_id: Word,
    /// Account list
    pub accounts: Vec<Account>,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: eth_types::Block<Transaction>,
    /// Trace
    pub trace: GethExecTrace,
}

impl TestContext {
    pub fn new<FAcc, FTx, Fb, const NACC: usize>(
        bytecode: Vec<Bytecode>,
        history_hashes: Option<Vec<Word>>,
        func_tx: FTx,
        func_block: Fb,
        acc_fns: Vec<FAcc>,
    ) -> Result<Self, Error>
    where
        FTx: FnOnce(&mut MockTransaction, Vec<MockAccount>) -> &mut MockTransaction,
        Fb: FnOnce(&mut MockBlock, MockTransaction) -> &mut MockBlock,
        FAcc: FnOnce(&mut MockAccount) -> &mut MockAccount,
    {
        let accounts: Vec<MockAccount> = vec![MockAccount::default(); NACC]
            .iter_mut()
            .zip(acc_fns)
            .map(|(acc, acc_fn)| acc_fn(acc).build())
            .collect();

        let mut tx = MockTransaction::default();
        func_tx(&mut tx, accounts.clone()).build();

        let mut block = MockBlock::default();
        func_block(&mut block, tx).build();

        let transactions: Vec<Transaction> = block
            .transactions
            .iter()
            .cloned()
            .map(|tx| Transaction::from(tx))
            .collect();
        let block = Block::<Transaction>::from(block);
        let accounts: Vec<Account> = accounts
            .iter()
            .cloned()
            .map(|acc| Account::from(acc))
            .collect();

        let trace = gen_geth_trace(
            block.clone(),
            transactions.clone(),
            accounts.clone(),
            history_hashes.clone(),
        )?;

        Ok(Self {
            chain_id: transactions[0].chain_id.unwrap_or_default(),
            accounts,
            history_hashes: history_hashes.unwrap_or_default(),
            eth_block: block,
            trace,
        })
    }

    pub fn new_from_geth_data(code: &Bytecode) -> Self {
        unimplemented!()
    }
}

/// Create a new block with a single tx that executes the code found in the
/// account with address 0x0 (which can call code in the other accounts),
/// with the given gas limit.
/// The trace will be generated automatically with the external_tracer
/// from the accounts code.
fn gen_geth_trace(
    block: Block<Transaction>,
    transactions: Vec<Transaction>,
    accounts: Vec<Account>,
    history_hashes: Option<Vec<Word>>,
) -> Result<GethExecTrace, Error> {
    let trace_config = TraceConfig {
        chain_id: transactions[0].chain_id.unwrap_or_default(),
        history_hashes: history_hashes.unwrap_or_default(),
        block_constants: BlockConstants::try_from(&block)?,
        accounts: accounts
            .iter()
            .map(|account| (account.address, account.clone()))
            .collect(),
        transaction: eth_types::geth_types::Transaction::from_eth_tx(&transactions[0]),
    };
    trace(&trace_config)
}
