use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        table::BlockContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{circuit::Region, plonk::Error};
use std::convert::TryFrom;

#[derive(Clone, Debug)]
pub(crate) struct NumberGadget<F> {
    same_context: SameContextGadget<F>,
    number: RandomLinearCombination<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for NumberGadget<F> {
    const NAME: &'static str = "NUMBER";

    const EXECUTION_STATE: ExecutionState = ExecutionState::NUMBER;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let number = cb.query_rlc();

        // Push the value to the stack
        cb.stack_push(number.expr());

        // Lookup block table with number
        cb.block_lookup(
            BlockContextFieldTag::Number.expr(),
            None,
            from_bytes::expr(&number.cells),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::NUMBER.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            number,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let number = block.rws[step.rw_indices[0]].stack_value();

        self.number.assign(
            region,
            offset,
            Some(u64::try_from(number).unwrap().to_le_bytes()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode;

    #[test]
    fn number_gadget_test() {
        let bytecode = bytecode! {
            #[start]
            NUMBER
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }
}
