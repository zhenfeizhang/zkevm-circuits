//! This module generates traces by connecting to an external tracer
use crate::Error;
use eth_types::{self, Address, Block, Bytes, GethExecTrace, Word, U64};
use geth_utils;
use serde::Serialize;
use std::collections::HashMap;

/// Definition of all of the constants related to an Ethereum block and
/// chain to be used as setup for the external tracer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants {
    /// coinbase
    pub coinbase: Address,
    /// time
    pub timestamp: Word,
    /// number
    pub number: U64,
    /// difficulty
    pub difficulty: Word,
    /// gas limit
    pub gas_limit: Word,
    /// base fee
    pub base_fee: Word,
}

impl<TX> TryFrom<&Block<TX>> for BlockConstants {
    type Error = Error;

    fn try_from(block: &Block<TX>) -> Result<Self, Self::Error> {
        Ok(Self {
            coinbase: block.author,
            timestamp: block.timestamp,
            number: block.number.ok_or(Error::IncompleteBlock)?,
            difficulty: block.difficulty,
            gas_limit: block.gas_limit,
            base_fee: block.base_fee_per_gas.ok_or(Error::IncompleteBlock)?,
        })
    }
}

impl BlockConstants {
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        coinbase: Address,
        timestamp: Word,
        number: U64,
        difficulty: Word,
        gas_limit: Word,
        base_fee: Word,
    ) -> BlockConstants {
        BlockConstants {
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            base_fee,
        }
    }
}

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Transaction {
    /// From Address
    pub from: Address,
    /// To Address
    pub to: Option<Address>,
    /// Nonce
    pub nonce: Word,
    /// Gas Limit
    pub gas_limit: Word,
    /// Gas Limit
    pub value: Word,
    /// Gas Price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
    /// Call data
    pub call_data: Bytes,
    /// Access list
    pub access_list: Option<eth_types::AccessList>,
}

impl Transaction {
    /// Create Self from a web3 transaction
    pub fn from_eth_tx(tx: &eth_types::Transaction) -> Self {
        Self {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            gas_limit: tx.gas,
            value: tx.value,
            gas_price: tx.gas_price.unwrap_or_default(),
            gas_fee_cap: tx.max_priority_fee_per_gas.unwrap_or_default(),
            gas_tip_cap: tx.max_fee_per_gas.unwrap_or_default(),
            call_data: tx.input.clone(),
            access_list: tx.access_list.clone(),
        }
    }
}

/// Definition of all of the data related to an account.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Account {
    /// Address
    pub address: Address,
    /// nonce
    pub nonce: Word,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: Bytes,
    /// Storage
    pub storage: HashMap<Word, Word>,
}

/// Configuration structure for `geth_utlis::trace`
#[derive(Debug, Default, Clone, Serialize)]
pub struct TraceConfig {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// block constants
    pub block_constants: BlockConstants,
    /// accounts
    pub accounts: HashMap<Address, Account>,
    /// transaction
    pub transaction: Transaction,
}

/// Creates a trace for the specified config
pub fn trace(config: &TraceConfig) -> Result<GethExecTrace, Error> {
    // Get the trace
    let trace_string = geth_utils::trace(
        &serde_json::to_string(config).unwrap(),
    )
    .map_err(|error| match error {
        geth_utils::Error::TracingError(error) => Error::TracingError(error),
    })?;

    let trace =
        serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    Ok(trace)
}

#[cfg(test)]
mod trace_test {
    use crate::{bytecode, mock};

    // Make sure that fix_geth_trace_memory_size is called on the result
    // returned via the tracer, so that the memory at MSTORE is not expanded
    // (the size should be 0).
    #[test]
    fn msize_trace_test() {
        let code = bytecode! {
            #[start]
            PUSH1(0x80)
            PUSH1(0x40)
            MSTORE
            MSIZE
            STOP
        };

        let block =
            mock::BlockData::new_single_tx_trace_code_at_start(&code).unwrap();
        assert_eq!(block.geth_trace.struct_logs[2].memory.0.len(), 0);
    }
}
