use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::operation::{
    AccountField, AccountOp, CallContextField, StackOp, TxAccessListAccountOp,
};
use crate::{operation::RW, Error};
use eth_types::{
    evm_types::{eip150_gas, memory_expansion_gas_cost, GasCost},
    GethExecStep, ToWord,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::DUP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Call;

impl Opcode for Call {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        // TODO: tx_id should be retrievable somewhere.
        let tx_id = 1;

        // Currently we do `handle_call_create` before `gen_associated_ops`, so
        // the one that triggers this step is `caller_call`. And the call it
        // triggers is already prepared as `call`.
        let caller_call = state.caller_call().clone();
        let call = state.call().clone();

        let step = &steps[0];

        for (field, value) in [
            (CallContextField::TxId, tx_id.into()),
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (caller_call.is_persistent as u64).into(),
            ),
            (
                CallContextField::CallerAddress,
                caller_call.address.to_word(),
            ),
            (
                CallContextField::IsStatic,
                (caller_call.is_static as u64).into(),
            ),
            (CallContextField::Depth, caller_call.depth.into()),
        ] {
            state.push_call_context_op(
                RW::READ,
                // TODO: Review with Han why this is caller and not call.
                // If this is caller, it means that a
                // given call_id can have different values for each field
                // here (one for each callee of the
                // call).
                caller_call.call_id,
                field,
                value,
            );
        }

        for i in 0..7 {
            state.push_op(
                RW::READ,
                StackOp {
                    call_id: caller_call.call_id,
                    address: step.stack.nth_last_filled(i),
                    value: step.stack.nth_last(i)?,
                },
            );
        }
        state.push_op(
            RW::WRITE,
            StackOp {
                call_id: caller_call.call_id,
                address: step.stack.nth_last_filled(6),
                value: (call.is_success as u64).into(),
            },
        );

        let is_cold_access = state.sdb.add_account_to_access_list(call.address);
        state.push_op(
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address: call.address,
                value: true,
                value_prev: !is_cold_access,
            },
        );

        for (field, value) in [
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (call.is_persistent as u64).into(),
            ),
        ] {
            state.push_call_context_op(RW::READ, call.call_id, field, value);
        }

        let (found, caller_account) =
            state.sdb.get_account_mut(&call.caller_address);
        if !found {
            return Err(Error::AccountNotFound(call.caller_address));
        }
        let caller_balance_prev = caller_account.balance;
        let caller_balance = caller_account.balance - call.value;
        caller_account.balance = caller_balance;
        state.push_op(
            RW::WRITE,
            AccountOp {
                address: call.caller_address,
                field: AccountField::Balance,
                value: caller_balance,
                value_prev: caller_balance_prev,
            },
        );

        let (found, callee_account) = state.sdb.get_account_mut(&call.address);
        if !found {
            return Err(Error::AccountNotFound(call.address));
        }
        let is_account_empty = callee_account.is_empty();
        let callee_balance_prev = callee_account.balance;
        let callee_balance = callee_account.balance + call.value;
        callee_account.balance = callee_balance;
        state.push_op(
            RW::WRITE,
            AccountOp {
                address: call.address,
                field: AccountField::Balance,
                value: callee_balance,
                value_prev: callee_balance_prev,
            },
        );

        let (_, account) = state.sdb.get_account_mut(&call.address);
        for (field, value) in [
            (AccountField::Nonce, account.nonce),
            (AccountField::CodeHash, account.code_hash.to_word()),
        ] {
            state.push_op(
                RW::READ,
                AccountOp {
                    address: call.address,
                    field,
                    value,
                    value_prev: value,
                },
            );
        }

        // Calculate next_memory_word_size and callee_gas_left manually in case
        // there isn't next step (e.g. callee doesn't have code).
        let next_memory_word_size = [
            step.memory.word_size() as u64,
            (call.call_data_offset + call.call_data_length + 31) / 32,
            (call.return_data_offset + call.return_data_length + 31) / 32,
        ]
        .into_iter()
        .max()
        .unwrap();
        let has_value = !call.value.is_zero();
        let gas_cost = GasCost::WARM_ACCESS.0
            + if is_cold_access {
                GasCost::EXTRA_COLD_ACCESS_ACCOUNT.0
            } else {
                0
            }
            + if is_account_empty {
                GasCost::CALL_EMPTY_ACCOUNT.0
            } else {
                0
            }
            + if has_value {
                GasCost::CALL_WITH_VALUE.0
            } else {
                0
            }
            + memory_expansion_gas_cost(
                step.memory.word_size() as u64,
                next_memory_word_size,
            );
        let callee_gas_left =
            eip150_gas(step.gas.0 - gas_cost, step.stack.last()?);

        for (field, value) in [
            (
                CallContextField::IsRoot,
                (caller_call.is_root as u64).into(),
            ),
            (
                CallContextField::IsCreate,
                (caller_call.is_create() as u64).into(),
            ),
            (
                CallContextField::CodeSource,
                caller_call.code_hash.to_word(),
            ),
            (CallContextField::ProgramCounter, (step.pc.0 + 1).into()),
            (
                CallContextField::StackPointer,
                (step.stack.stack_pointer().0 + 6).into(),
            ),
            (
                CallContextField::GasLeft,
                (step.gas.0 - gas_cost - callee_gas_left).into(),
            ),
            (CallContextField::MemorySize, next_memory_word_size.into()),
            (
                CallContextField::StateWriteCounter,
                state.caller_ctx().swc.into(),
            ),
        ] {
            state.push_call_context_op(
                RW::WRITE,
                caller_call.call_id,
                field,
                value,
            );
        }

        for (field, value) in [
            (CallContextField::CallerId, caller_call.call_id.into()),
            (CallContextField::TxId, tx_id.into()),
            (CallContextField::Depth, call.depth.into()),
            (
                CallContextField::CallerAddress,
                call.caller_address.to_word(),
            ),
            (CallContextField::CalleeAddress, call.address.to_word()),
            (
                CallContextField::CallDataOffset,
                call.call_data_offset.into(),
            ),
            (
                CallContextField::CallDataLength,
                call.call_data_length.into(),
            ),
            (
                CallContextField::ReturnDataOffset,
                call.return_data_offset.into(),
            ),
            (
                CallContextField::ReturnDataLength,
                call.return_data_length.into(),
            ),
            (CallContextField::Value, call.value),
            (CallContextField::IsSuccess, (call.is_success as u64).into()),
            (CallContextField::IsStatic, (call.is_static as u64).into()),
            (CallContextField::LastCalleeId, 0.into()),
            (CallContextField::LastCalleeReturnDataOffset, 0.into()),
            (CallContextField::LastCalleeReturnDataLength, 0.into()),
        ] {
            state.push_call_context_op(RW::READ, call.call_id, field, value);
        }

        Ok(())
    }
}
