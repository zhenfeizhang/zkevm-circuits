use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::{GethExecStep, ToWord};
use crate::operation::{
    AccountField, AccountOp, CallContextField, CallContextOp, StackOp,
    TxAccessListAccountOp,
};
use crate::{operation::RW, Error};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::DUP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Call;

impl Opcode for Call {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let tx_id = 1;
        let caller_call = state.caller_call().clone();
        let call = state.call().clone();
        let step = &steps[0];
        let next_step = &steps[1];

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
            state.push_op(CallContextOp {
                rw: RW::READ,
                call_id: caller_call.call_id,
                field,
                value,
            });
        }

        for i in 0..7 {
            state.push_op(StackOp {
                rw: RW::READ,
                call_id: caller_call.call_id,
                address: step.stack.nth_last_filled(i),
                value: step.stack.nth_last(i)?,
            });
        }
        state.push_op(StackOp {
            rw: RW::WRITE,
            call_id: caller_call.call_id,
            address: step.stack.nth_last_filled(6),
            value: (call.is_success as u64).into(),
        });

        let value_prev = state.sdb.add_account_to_access_list(call.address);
        state.push_op(TxAccessListAccountOp {
            tx_id,
            address: call.address,
            value: true,
            value_prev,
        });
        state
            .caller_ctx_mut()
            .push_op_reverted(TxAccessListAccountOp {
                tx_id,
                address: call.address,
                value: value_prev,
                value_prev: true,
            });

        for (field, value) in [
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (call.is_persistent as u64).into(),
            ),
        ] {
            state.push_op(CallContextOp {
                rw: RW::READ,
                call_id: call.call_id,
                field,
                value,
            });
        }

        let (found, caller_account) =
            state.sdb.get_account_mut(&call.caller_address);
        if !found {
            return Err(Error::AccountNotFound(call.caller_address));
        }
        let caller_balance_prev = caller_account.balance;
        let caller_balance = caller_account.balance - call.value;
        caller_account.balance = caller_balance;
        state.push_op(AccountOp {
            rw: RW::WRITE,
            address: call.caller_address,
            field: AccountField::Balance,
            value: caller_balance,
            value_prev: caller_balance_prev,
        });
        state.call_ctx_mut().push_op_reverted(AccountOp {
            rw: RW::WRITE,
            address: call.caller_address,
            field: AccountField::Balance,
            value: caller_balance_prev,
            value_prev: caller_balance,
        });

        let (found, callee_account) = state.sdb.get_account_mut(&call.address);
        if !found {
            return Err(Error::AccountNotFound(call.address));
        }
        let callee_balance_prev = callee_account.balance;
        let callee_balance = callee_account.balance + call.value;
        callee_account.balance = callee_balance;
        state.push_op(AccountOp {
            rw: RW::WRITE,
            address: call.address,
            field: AccountField::Balance,
            value: callee_balance,
            value_prev: callee_balance_prev,
        });
        state.call_ctx_mut().push_op_reverted(AccountOp {
            rw: RW::WRITE,
            address: call.address,
            field: AccountField::Balance,
            value: callee_balance_prev,
            value_prev: callee_balance,
        });

        let (_, account) = state.sdb.get_account_mut(&call.address);
        for (field, value) in [
            (AccountField::Nonce, account.nonce),
            (AccountField::CodeHash, account.code_hash.to_word()),
        ] {
            state.push_op(AccountOp {
                rw: RW::READ,
                address: call.address,
                field,
                value,
                value_prev: value,
            });
        }

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
                (step.gas.0
                    - step.gas_cost.0
                    - (next_step.gas.0
                        - if call.value.is_zero() { 0 } else { 2300 }))
                .into(),
            ),
            (
                CallContextField::MemorySize,
                (*[
                    step.memory.size() as u64,
                    (call.call_data_offset + call.call_data_length + 31) / 32,
                    (call.return_data_offset + call.return_data_length + 31)
                        / 32,
                ]
                .iter()
                .min()
                .unwrap())
                .into(),
            ),
            (
                CallContextField::StateWriteCounter,
                state.caller_ctx().swc.into(),
            ),
        ] {
            state.push_op(CallContextOp {
                rw: RW::WRITE,
                call_id: caller_call.call_id,
                field,
                value,
            });
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
            state.push_op(CallContextOp {
                rw: RW::READ,
                call_id: call.call_id,
                field,
                value,
            });
        }

        Ok(())
    }
}
