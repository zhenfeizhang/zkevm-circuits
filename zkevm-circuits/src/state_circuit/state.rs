use crate::{
    evm_circuit::util::RandomLinearCombination,
    gadget::{
        is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
        monotone::{MonotoneChip, MonotoneConfig},
        Variable,
    },
};
use bus_mapping::operation::{MemoryOp, Operation, StackOp, StorageOp};
use eth_types::{ToLittleEndian, ToScalar};
use halo2::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use pairing::arithmetic::FieldExt;

/*
Example state table:

| tag       | address | rw_counter | value | flag_write | flag_padding | storage_key | value_prev |
| ---       | ---     | ---        | ---   | ---        | ---          | ---         | ---        |
| 1:Start   | 0       | 0          | 0     | 1          | 0            |             |            | // init row (write value 0)
| 2:Memory  | 0       | 12         | 12    | 1          | 0            |             |            |
| 2:Memory  | 0       | 24         | 12    | 0          | 0            |             |            |
| 2:Memory  | 1       | 0          | 0     | 1          | 0            |             |            | // init row (write value 0)
| 2:Memory  | 1       | 2          | 12    | 0          | 0            |             |            |
| 2:Memory  |         |            |       |            | 1            |             |            | // padding
| 2:Memory  |         |            |       |            | 1            |             |            | // padding
| 1:Start   | 0       | 3          | 4     | 1          | 0            |             |            |
| 3:Stack   | 0       | 17         | 32    | 1          | 0            |             |            |
| 3:Stack   | 0       | 89         | 32    | 0          | 0            |             |            |
| 3:Stack   | 1       | 48         | 32    | 1          | 0            |             |            |
| 3:Stack   | 1       | 49         | 32    | 0          | 0            |             |            |
| 3:Stack   |         |            |       |            | 1            |             |            | // padding
| 1:Start   | 1       | 55         | 32    | 1          | 0            | 5           | 0          | // first storage op at the new address has to be write
| 4:Storage | 1       | 56         | 33    | 1          | 0            | 8           | 32         |
| 4:Storage |         |            |       |            | 1            |             |            | // padding
*/

/* Memory

| Key1 (Tag) | Key2   | Key3    | Key4 | RWC | Write | Value1 | Aux1 | Aux2 |
| ---        | ---    | ---     | ---  | --- | ---   | ---    | ---  | ---  |
|            | CallID | MemAddr | -    |     |       |        |      |      |
| 1:Start    |

*/

// tag:
// 1 - first row of each tag (Note: only the first row, not all init rows)
// 2 - memory
// 3 - stack
// 4 - storage

// address presents memory address, stack pointer, and account address for
// memory, stack, and storage ops respectively two columns are not displayed:
// address_diff and storage_key_diff (needed to check whether the address or
// storage_key changed) storage_key and value_prev are needed for storage ops
// only flag_padding specifies whether the row is just a padding to fill all the
// rows that are intended for a particular tag

/*
Example bus mapping:
// TODO: this is going to change

| tag   | address | rw_counter | value | storage_key | value_prev | flag_write |
| ---      | ---     | ---        | ---   | ---         | ---        | ---     |
| 2:Memory | 0       | 12         | 12    |             |            | 1       |
| 2:Memory | 0       | 24         | 12    |             |            | 0       |
| 2:Memory | 1       | 2          | 12    |             |            | 0       |
| 1:Start  | 0       | 3          | 4     |             |            | 1       |
| 3:Stack  | 0       | 17         | 32    |             |            | 1       |
| 3:Stack  | 0       | 89         | 32    |             |            | 0       |
| 3:Stack  | 1       | 48         | 32    |             |            | 1       |
| 3:Stack  | 1       | 49         | 32    |             |            | 0       |
*/

/// Number of Tag variants
pub const TAG_COUNT: usize = 9;

/// Possible Tag values
#[derive(Clone, Copy)]
pub enum Tag {
    Start = 1,
    Memory = 2,
    Stack = 3,
    Storage = 4,
    CallContext = 5,
    Account = 6,
    TxRefund = 7,
    TxAccessListAccountStorage = 8,
    TxAccessListAccount = 9,
}

/// Expression that evaluates to != 0 when x == target and 0 otherwise, asuming
/// that x is in the `iter` range.
fn _in_range_eq_const<F: FieldExt, I: Iterator<Item = usize>>(
    x: Expression<F>,
    iter: I,
    target: usize,
) -> Expression<F> {
    let mut e = Expression::Constant(F::from(1));
    for i in iter {
        let i_expr = Expression::Constant(F::from(i as u64));
        if i != target {
            e = e * (x.clone() - i_expr);
        }
    }
    e
}

/// Expression that evaluates to 1 when x == target and 0 otherwise, asuming
/// that x is in the `iter` range.
/// The expression is built using the Lagrange interpolation.
fn in_range_eq_const<F: FieldExt, I: Iterator<Item = usize> + Clone>(
    x: Expression<F>,
    iter: I,
    target: usize,
) -> Expression<F> {
    // Evaluate expresion when x == target
    let mut n = F::one();
    let target_f = F::from(target as u64);
    for i in iter.clone() {
        if i != target {
            n *= target_f - F::from(i as u64);
        }
    }
    // Normalize result when x == target
    _in_range_eq_const(x, iter, target) * n.invert().unwrap()
}

/// A mapping derived from witnessed memory operations.
/// TODO: The complete version of this mapping will involve storage, stack,
/// and opcode details as well.
#[derive(Clone, Debug)]
pub(crate) struct BusMapping<F: FieldExt> {
    rw_counter: Variable<usize, F>,
    tag: Variable<usize, F>,
    flag_write: Variable<bool, F>,
    address: Variable<F, F>,
    storage_key: Variable<F, F>,
    value: Variable<F, F>,
    value_prev: Variable<F, F>,
}

#[derive(Debug, Default)]
pub struct StateCircuitParams {
    pub sanity_check: bool,
    pub rw_counter_max: usize,
    pub memory_rows_max: usize,
    pub stack_rows_max: usize,
    pub storage_rows_max: usize,
    pub stack_address_max: usize,
    pub memory_address_max: usize,
}

#[derive(Clone, Debug)]
pub struct Config<F: FieldExt, const MEMORY_ADDRESS_MAX: usize, const STACK_ADDRESS_MAX: usize> {
    tag: Column<Fixed>, // Key 1 (Tag)
    // TODO: Key 2
    address: Column<Advice>, /* Key 3. Used for memory address, stack pointer, and
                              * account address (for storage) */
    // TODO: Key 4
    address_diff_inv: Column<Advice>,
    rw_counter: Column<Advice>,
    value: Column<Advice>, // Value 1
    // TODO: Aux 1
    // TODO: Aux 2
    flag_write: Column<Advice>,
    flag_padding: Column<Advice>, // Binary flag: wether this row is padding.
    storage_key: Column<Advice>,
    storage_key_diff_inv: Column<Advice>,
    value_prev: Column<Advice>,
    rw_counter_table: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
    memory_value_table: Column<Fixed>,
    address_diff_is_zero: IsZeroConfig<F>,
    address_monotone: MonotoneConfig,
    padding_monotone: MonotoneConfig,
    storage_key_diff_is_zero: IsZeroConfig<F>,
}

impl<F: FieldExt, const MEMORY_ADDRESS_MAX: usize, const STACK_ADDRESS_MAX: usize>
    Config<F, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX>
{
    /// Set up custom gates and lookup arguments for this configuration.
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let tag = meta.fixed_column();
        let address = meta.advice_column();
        let address_diff_inv = meta.advice_column();
        let rw_counter = meta.advice_column();
        let value = meta.advice_column();
        let flag_write = meta.advice_column();
        let flag_padding = meta.advice_column();
        let storage_key = meta.advice_column();
        let storage_key_diff_inv = meta.advice_column();
        let value_prev = meta.advice_column();
        let rw_counter_table = meta.fixed_column();
        let memory_address_table_zero = meta.fixed_column();
        let stack_address_table_zero = meta.fixed_column();
        let memory_value_table = meta.fixed_column();

        let one = Expression::Constant(F::one());
        let tag_first = Expression::Constant(F::from(Tag::Start as u64));

        // First tag row.  Expr that evaluates to 1 when tag_cur = 1 and
        // tag_next = target, 0 otherwise.
        let is_tag_first = |meta: &mut VirtualCells<F>, target: Tag| {
            let tag_cur = meta.query_fixed(tag, Rotation::cur());
            let tag_next = meta.query_fixed(tag, Rotation::next());

            tag_cur.clone()
                * F::from(Tag::Start as u64).invert().unwrap()
                * in_range_eq_const(tag_cur, 1..=TAG_COUNT, Tag::Start as usize)
                * in_range_eq_const(tag_next, 1..=TAG_COUNT, target as usize)
        };

        // Non first tag row.  Expr that evaluates to 1 when tag_cur = target, 0
        // otherwise.
        let is_tag_not_first = |meta: &mut VirtualCells<F>, target: Tag| {
            let tag = meta.query_fixed(tag, Rotation::cur());

            tag.clone()
                * F::from(target as u64).invert().unwrap()
                * in_range_eq_const(tag, 1..=TAG_COUNT, target as usize)
        };

        let is_memory_first = |meta: &mut VirtualCells<F>| is_tag_first(meta, Tag::Memory);
        let is_memory_not_first = |meta: &mut VirtualCells<F>| is_tag_not_first(meta, Tag::Memory);
        let is_stack_first = |meta: &mut VirtualCells<F>| is_tag_first(meta, Tag::Stack);
        let is_stack_not_first = |meta: &mut VirtualCells<F>| is_tag_not_first(meta, Tag::Stack);
        let is_storage_first = |meta: &mut VirtualCells<F>| is_tag_first(meta, Tag::Storage);
        let is_storage_not_first =
            |meta: &mut VirtualCells<F>| is_tag_not_first(meta, Tag::Storage);

        // NOTE(Edu): This is not binary!
        let address_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
                let flag_not_padding = one.clone() - flag_padding;
                let tag = meta.query_fixed(tag, Rotation::cur());
                // tag = Tag::First -> 0
                // tag = Tag::* -> != 0
                // >2 otherwise
                // NOTE(Edu): This is not binary!
                let flag_not_first = tag.clone() * (tag - tag_first.clone());

                flag_not_first * flag_not_padding
            },
            |meta| {
                let address_cur = meta.query_advice(address, Rotation::cur());
                let address_prev = meta.query_advice(address, Rotation::prev());
                address_cur - address_prev
            },
            address_diff_inv,
        );

        // NOTE(Edu):  `address` column is sorted for memory and stack Tag.
        // Only one monotone gadget is used for Memory AND Stack (with
        // MEMORY_ADDRESS_MAX as it is bigger)
        let address_monotone = MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::configure(
            meta,
            |meta| {
                let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
                let flag_not_padding = one.clone() - flag_padding;
                // Since q_memory_not_first and q_stack_non_first are
                // mutually exclusive, q_not_first is binary.
                let q_not_first = is_memory_not_first(meta) + is_stack_not_first(meta);

                q_not_first * flag_not_padding
            },
            address,
        );

        // NOTE(Edu): `flag_padding` can only transition from 0 to 1, for Memory
        // AND Stack.
        // flag_padding monotonicity could be checked using gates (as flag_padding only
        // takes values 0 and 1), but it's much slower than using a
        // lookup.
        let padding_monotone = MonotoneChip::<F, 1, true, false>::configure(
            meta,
            |meta| is_memory_not_first(meta) + is_stack_not_first(meta),
            flag_padding,
        );

        // A gate for the first row (does not need Rotation::prev).
        meta.create_gate("First memory row operation", |meta| {
            let value = meta.query_advice(value, Rotation::cur());
            let flag_write = meta.query_advice(flag_write, Rotation::cur());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            // NOTE(Edu):  `q_memory_first` is only true for the first row.
            let q_memory_first = is_memory_first(meta);

            //
            //      - values[0] == [0]
            //      - flag_writes[0] == 1
            //      - rw_counters[0] == 0

            vec![
                q_memory_first.clone() * value,
                q_memory_first.clone() * (one.clone() - flag_write),
                q_memory_first * rw_counter,
            ]
        });

        meta.create_gate("Memory operation + flag_padding", |meta| {
            // If address_cur != address_prev, this is an `init`. We must
            // constrain:
            //      - values[0] == [0]
            //      - flag_writes[0] == 1
            //      - rw_counters[0] == 0
            let q_memory_not_first = is_memory_not_first(meta);
            let address_diff = {
                let address_prev = meta.query_advice(address, Rotation::prev());
                let address_cur = meta.query_advice(address, Rotation::cur());
                address_cur - address_prev
            };

            let value_cur = meta.query_advice(value, Rotation::cur());
            let flag_write = meta.query_advice(flag_write, Rotation::cur());
            let rw_counter =
                meta.query_advice(rw_counter, Rotation::cur());

            // If flag_write == 0 (read), and rw_counter != 0, value_prev ==
            // value_cur
            let value_prev = meta.query_advice(value, Rotation::prev());
            let flag_read = one.clone() - flag_write;

            vec![
                q_memory_not_first.clone()
                    * address_diff.clone()
                    * value_cur.clone(), // when address changes, the write value is 0
                q_memory_not_first.clone()
                    * address_diff.clone()
                    * flag_read.clone(), // when address changes, the flag_write is 1 (write)
                q_memory_not_first.clone() * address_diff * rw_counter, // when address changes, rw_counter is 0
                q_memory_not_first * flag_read * (value_cur - value_prev), // when reading, the value is the same as at the previous op
                // Note that this last constraint needs to hold only when address doesn't change,
                // but we don't need to check this as the first operation at the address always
                // has to be write - that means flag_read is 1 only when
                // the address and storage key don't change.
            ]
        });

        // NOTE(Edu): I've removed the advice columns boolean constraints for each
        // particular Tag and grouped them all into these gates because they
        // apply to all Tags. Boolean advice column constraints

        meta.create_gate("flag_write bool", |meta| {
            let tag = meta.query_fixed(tag, Rotation::cur());
            let flag_write = meta.query_advice(flag_write, Rotation::cur());
            // flag_write == 0 or 1
            // (flag_write) * (1 - flag_write)
            let bool_check = flag_write.clone() * (one.clone() - flag_write.clone());

            // tag > 0 enables the constraint for flag_write to bee boolean.
            vec![tag * bool_check]
        });

        meta.create_gate("flag_padding bool", |meta| {
            let tag = meta.query_fixed(tag, Rotation::cur());
            let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
            // flag_padding == 0 or 1
            // (flag_padding) * (1 - flag_padding)
            let bool_check = flag_padding.clone() * (one.clone() - flag_padding.clone());

            // tag > 0 enables the constraint for flag_padding to bee boolean.
            vec![tag * bool_check]
        });

        // We don't require first stack op to be write as this is enforced by
        // evm circuit.

        meta.create_gate("Stack operation", |meta| {
            let q_stack_not_first = is_stack_not_first(meta);
            let value_cur = meta.query_advice(value, Rotation::cur());
            let flag_write = meta.query_advice(flag_write, Rotation::cur());

            // If flag_write == 0 (read), and rw_counter != 0, value_prev == value_cur
            let value_prev = meta.query_advice(value, Rotation::prev());
            let flag_read = one.clone() - flag_write;
            // when addresses changes, we don't require the operation is write as this is
            // enforced by evm circuit

            vec![
                q_stack_not_first * flag_read * (value_cur - value_prev), /* when reading, the
                                                                           * value is the same
                                                                           * as
                                                                           * at the previous op */
            ]
        });

        // rw_counter monotonicity is checked for memory and stack when
        // address_cur == address_prev. (Recall that operations are
        // ordered first by address, and then by rw_counter.)
        meta.lookup_any(|meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
            let flag_not_padding = one.clone() - flag_padding;
            let q_not_first = is_memory_not_first(meta) + is_stack_not_first(meta);

            vec![(
                q_not_first
                    * flag_not_padding
                    * address_diff_is_zero.clone().is_zero_expression
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        // Memory address is in the allowed range.
        meta.lookup_any(|meta| {
            let q_memory = is_memory_first(meta) + is_memory_not_first(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let memory_address_table_zero =
                meta.query_fixed(memory_address_table_zero, Rotation::cur());

            vec![(q_memory * address_cur, memory_address_table_zero)]
        });

        // Stack address is in the allowed range.
        meta.lookup_any(|meta| {
            let q_stack = is_stack_first(meta) + is_stack_not_first(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let stack_address_table_zero =
                meta.query_fixed(stack_address_table_zero, Rotation::cur());

            vec![(q_stack * address_cur, stack_address_table_zero)]
        });

        // rw_counter is in the allowed range:
        meta.lookup_any(|meta| {
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());

            vec![(rw_counter, rw_counter_table)]
        });

        // Memory value (for non-first rows) is in the allowed range.
        // Memory first row value doesn't need to be checked - it is checked
        // above where memory init row value has to be 0.
        meta.lookup_any(|meta| {
            let q_memory_not_first = is_memory_not_first(meta);
            let value = meta.query_advice(value, Rotation::cur());
            let memory_value_table = meta.query_fixed(memory_value_table, Rotation::cur());

            vec![(q_memory_not_first * value, memory_value_table)]
        });

        // NOTE(Edu): This is not binary!
        let storage_key_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
                let flag_not_padding = one.clone() - flag_padding;

                let tag = meta.query_fixed(tag, Rotation::cur());
                // tag = Tag::First -> 0
                // tag = Tag::* -> != 0
                // >2 otherwise
                // NOTE(Edu): This is not binary!
                let q_not_first = tag.clone() * (tag - tag_first.clone());

                q_not_first * flag_not_padding
            },
            |meta| {
                let storage_key_cur = meta.query_advice(storage_key, Rotation::cur());
                let storage_key_prev = meta.query_advice(storage_key, Rotation::prev());
                storage_key_cur - storage_key_prev
            },
            storage_key_diff_inv,
        );

        meta.create_gate("First storage row operation", |meta| {
            let flag_write = meta.query_advice(flag_write, Rotation::cur());
            let flag_read = one.clone() - flag_write;

            vec![
                is_storage_first(meta) * flag_read, /* first storage op has to be
                                                     * write (flag_write = 1) */
            ]
        });

        meta.create_gate("Storage operation", |meta| {
            let q_storage_not_first = is_storage_not_first(meta);
            let address_diff = {
                let address_prev = meta.query_advice(address, Rotation::prev());
                let address_cur = meta.query_advice(address, Rotation::cur());
                address_cur - address_prev
            };

            let storage_key_diff = {
                let storage_key_prev =
                    meta.query_advice(storage_key, Rotation::prev());
                let storage_key_cur =
                    meta.query_advice(storage_key, Rotation::cur());
                storage_key_cur - storage_key_prev
            };

            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev_cur = meta.query_advice(value_prev, Rotation::cur());
            let value_prev_prev =
                meta.query_advice(value_prev, Rotation::prev());
            let flag_write = meta.query_advice(flag_write, Rotation::cur());

            // If flag_write == 0 (read), and rw_counter != 0, value_prev == value_cur
            let value_previous = meta.query_advice(value, Rotation::prev());
            let flag_read = one.clone() - flag_write.clone();

            let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
            let flag_not_padding = one.clone() - flag_padding;

            vec![
                q_storage_not_first.clone() * address_diff * flag_read.clone(), // when address changes, the flag_read is 0 (write)
                q_storage_not_first.clone() * storage_key_diff * flag_read.clone(), // when storage_key_diff changes, the flag_read is 0 (write)
                q_storage_not_first.clone()
                    * flag_read.clone()
                    * (value_cur - value_previous.clone()), // when reading, the value is the same as at the previous op
                // Note that this last constraint needs to hold only when address and storage key don't change,
                // but we don't need to check this as the first operation at new address and
                // new storage key always has to be write - that means flag_read is 1 only when
                // the address and storage key doesn't change.
                flag_not_padding.clone()
                    * flag_write
                    * q_storage_not_first.clone()
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (value_prev_cur.clone() - value_previous),
                flag_not_padding
                    * flag_read
                    * q_storage_not_first
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (value_prev_cur - value_prev_prev),
            ]
        });

        // rw_counter monotonicity is checked for storage when address_cur
        // == address_prev and storage_key_cur = storage_key_prev.
        // (Recall that storage operations are ordered first by account address,
        // then by storage_key, and finally by rw_counter.)

        meta.lookup_any(|meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let flag_padding = meta.query_advice(flag_padding, Rotation::cur());
            let flag_not_padding = one.clone() - flag_padding;
            let q_storage_not_first = is_storage_not_first(meta);

            vec![(
                q_storage_not_first
                    * flag_not_padding
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        // TODO: monotone address for storage

        Config {
            tag,
            address,
            address_diff_inv,
            rw_counter,
            value,
            flag_write,
            flag_padding,
            storage_key,
            storage_key_diff_inv,
            value_prev,
            rw_counter_table,
            memory_address_table_zero,
            stack_address_table_zero,
            memory_value_table,
            address_diff_is_zero,
            address_monotone,
            padding_monotone,
            storage_key_diff_is_zero,
        }
    }

    /// Load lookup table / other fixed constants for this configuration.
    pub(crate) fn load(
        &self,
        params: &StateCircuitParams,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter
            .assign_region(
                || "rw_counter table",
                |mut region| {
                    for idx in 0..=params.rw_counter_max {
                        region.assign_fixed(
                            || format!("rw_counter {}", idx),
                            self.rw_counter_table,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter
            .assign_region(
                || "memory value table",
                |mut region| {
                    for idx in 0..=255 {
                        region.assign_fixed(
                            || format!("memory value {}", idx),
                            self.memory_value_table,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter
            .assign_region(
                || "memory address table with zero",
                |mut region| {
                    for idx in 0..=params.memory_address_max {
                        region.assign_fixed(
                            || format!("address with zero {}", idx),
                            self.memory_address_table_zero,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter.assign_region(
            || "stack address table with zero",
            |mut region| {
                for idx in 0..=params.stack_address_max {
                    region.assign_fixed(
                        || format!("stack address with zero {}", idx),
                        self.stack_address_table_zero,
                        idx,
                        || Ok(F::from(idx as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    fn assign_memory_ops(
        &self,
        params: &StateCircuitParams,
        region: &mut Region<F>,
        _randomness: F,
        ops: Vec<Operation<MemoryOp>>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        let mut init_rows_num = 0;
        for (index, oper) in ops.iter().enumerate() {
            let op = oper.op();
            if index > 0 {
                if op.address() != ops[index - 1].op().address() {
                    init_rows_num += 1;
                }
            } else {
                init_rows_num += 1;
            }
        }

        if ops.len() + init_rows_num > params.memory_rows_max {
            panic!("too many memory operations");
        }

        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut address_prev = F::zero();
        let mut offset = 0;
        for (index, oper) in ops.iter().enumerate() {
            let op = oper.op();
            let address = F::from_bytes(&op.address().to_le_bytes()).unwrap();
            if params.sanity_check && address > F::from(MEMORY_ADDRESS_MAX as u64) {
                panic!(
                    "memory address out of range {:?} > {}",
                    address, MEMORY_ADDRESS_MAX
                );
            }
            let rwc = usize::from(oper.rwc());
            // value of memory op is of type u8, so random_linear_combine is not
            // needed here.
            let val = F::from(op.value() as u64);
            let mut tag = Tag::Start as usize;
            if index > 0 {
                tag = Tag::Memory as usize;
            }

            // memory ops have init row
            if index == 0 || address != address_prev {
                self.init(region, offset, address, tag)?;
                address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;
                tag = 2;
                offset += 1;
            }

            let bus_mapping = self.assign_op(
                params,
                region,
                offset,
                address,
                rwc,
                val,
                op.rw().is_write(),
                tag,
                F::zero(),
                F::zero(),
            )?;
            bus_mappings.push(bus_mapping);

            address_prev = address;
            offset += 1;
        }

        self.pad_rows(region, offset, 0, params.memory_rows_max, 2)?;

        Ok(bus_mappings)
    }

    fn assign_stack_ops(
        &self,
        params: &StateCircuitParams,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Operation<StackOp>>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        if ops.len() > params.stack_rows_max {
            panic!("too many stack operations");
        }
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut address_prev = F::zero();
        let mut offset = params.memory_rows_max;
        for (index, oper) in ops.iter().enumerate() {
            let op = oper.op();
            if params.sanity_check && usize::from(*op.address()) > STACK_ADDRESS_MAX {
                panic!("stack address out of range");
            }
            let address = F::from(usize::from(*op.address()) as u64);
            let rwc = usize::from(oper.rwc());
            let val = RandomLinearCombination::random_linear_combine(
                op.value().to_le_bytes(),
                randomness,
            );
            let mut tag = Tag::Start as usize;
            if index > 0 {
                tag = Tag::Stack as usize;
            }

            let bus_mapping = self.assign_op(
                params,
                region,
                offset,
                address,
                rwc,
                val,
                op.rw().is_write(),
                tag,
                F::zero(),
                F::zero(),
            )?;
            bus_mappings.push(bus_mapping);

            address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;

            address_prev = address;
            offset += 1;
        }

        self.pad_rows(
            region,
            offset,
            params.memory_rows_max,
            params.stack_rows_max,
            3,
        )?;

        Ok(bus_mappings)
    }

    fn assign_storage_ops(
        &self,
        params: &StateCircuitParams,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Operation<StorageOp>>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        storage_key_diff_is_zero_chip: &IsZeroChip<F>,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        if ops.len() > params.storage_rows_max {
            panic!("too many storage operations");
        }
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut address_prev = F::zero();
        let mut storage_key_prev = F::zero();
        let mut offset = params.memory_rows_max + params.stack_rows_max;
        for (index, oper) in ops.iter().enumerate() {
            let op = oper.op();
            let rwc = usize::from(oper.rwc());

            // address in 160bits, so it can be put into F.
            // random_linear_combine is not needed here.
            let address = op.address().to_scalar().unwrap();

            let val = RandomLinearCombination::random_linear_combine(
                op.value().to_le_bytes(),
                randomness,
            );
            let val_prev = RandomLinearCombination::random_linear_combine(
                op.value_prev().to_le_bytes(),
                randomness,
            );
            let storage_key =
                RandomLinearCombination::random_linear_combine(op.key().to_le_bytes(), randomness);

            let mut tag = Tag::Start as usize;
            if index > 0 {
                tag = Tag::Storage as usize;
            }

            let bus_mapping = self.assign_op(
                params,
                region,
                offset,
                address,
                rwc,
                val,
                op.rw().is_write(),
                tag,
                storage_key,
                val_prev,
            )?;
            bus_mappings.push(bus_mapping);

            address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;

            storage_key_diff_is_zero_chip.assign(
                region,
                offset,
                Some(storage_key - storage_key_prev),
            )?;

            address_prev = address;
            storage_key_prev = storage_key;
            offset += 1;
        }

        self.pad_rows(
            region,
            offset,
            params.memory_rows_max + params.stack_rows_max,
            params.storage_rows_max,
            4,
        )?;

        Ok(bus_mappings)
    }

    fn pad_rows(
        &self,
        region: &mut Region<F>,
        offset: usize,
        start_offset: usize,
        max_rows: usize,
        tag: usize,
    ) -> Result<(), Error> {
        // We pad all remaining rows to avoid the check at the first unused row.
        // Without flag_padding, (address_cur - address_prev) would not be zero at
        // the first unused row and some checks would be triggered.

        for i in offset..start_offset + max_rows {
            if i == start_offset {
                region.assign_fixed(|| "tag", self.tag, i, || Ok(F::one()))?;
            } else {
                region.assign_fixed(|| "tag", self.tag, i, || Ok(F::from(tag as u64)))?;
            }
            region.assign_advice(|| "flag_padding", self.flag_padding, i, || Ok(F::one()))?;
            region.assign_advice(|| "memory", self.flag_write, i, || Ok(F::one()))?;
        }

        Ok(())
    }

    /// Assign cells.
    pub(crate) fn assign(
        &self,
        params: &StateCircuitParams,
        mut layouter: impl Layouter<F>,
        randomness: F,
        memory_ops: Vec<Operation<MemoryOp>>,
        stack_ops: Vec<Operation<StackOp>>,
        storage_ops: Vec<Operation<StorageOp>>,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let address_diff_is_zero_chip = IsZeroChip::construct(self.address_diff_is_zero.clone());

        let memory_address_monotone_chip =
            MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::construct(
                self.address_monotone.clone(),
            );
        memory_address_monotone_chip.load(&mut layouter)?;

        let padding_monotone_chip =
            MonotoneChip::<F, 1, true, false>::construct(self.padding_monotone.clone());
        padding_monotone_chip.load(&mut layouter)?;

        let storage_key_diff_is_zero_chip =
            IsZeroChip::construct(self.storage_key_diff_is_zero.clone());

        layouter.assign_region(
            || "State operations",
            |mut region| {
                let memory_mappings = self.assign_memory_ops(
                    params,
                    &mut region,
                    randomness,
                    memory_ops.clone(),
                    &address_diff_is_zero_chip,
                );
                bus_mappings.extend(memory_mappings.unwrap());

                let stack_mappings = self.assign_stack_ops(
                    params,
                    &mut region,
                    randomness,
                    stack_ops.clone(),
                    &address_diff_is_zero_chip,
                );
                bus_mappings.extend(stack_mappings.unwrap());

                let storage_mappings = self.assign_storage_ops(
                    params,
                    &mut region,
                    randomness,
                    storage_ops.clone(),
                    &address_diff_is_zero_chip,
                    &storage_key_diff_is_zero_chip,
                );
                bus_mappings.extend(storage_mappings.unwrap());

                Ok(bus_mappings.clone())
            },
        )
    }

    /// Initialise first row for a new operation.
    fn init(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: F,
        tag: usize,
    ) -> Result<(), Error> {
        region.assign_advice(|| "init address", self.address, offset, || Ok(address))?;

        region.assign_advice(
            || "init rw_counter",
            self.rw_counter,
            offset,
            || Ok(F::zero()),
        )?;

        region.assign_advice(|| "init value", self.value, offset, || Ok(F::zero()))?;

        region.assign_advice(|| "init memory", self.flag_write, offset, || Ok(F::one()))?;

        region.assign_fixed(|| "tag", self.tag, offset, || Ok(F::from(tag as u64)))?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_op(
        &self,
        params: &StateCircuitParams,
        region: &mut Region<'_, F>,
        offset: usize,
        address: F,
        rw_counter: usize,
        value: F,
        flag_write: bool,
        tag: usize,
        storage_key: F,
        value_prev: F,
    ) -> Result<BusMapping<F>, Error> {
        let address = {
            let cell = region.assign_advice(|| "address", self.address, offset, || Ok(address))?;
            Variable::<F, F> {
                cell,
                field_elem: Some(address),
                value: Some(address),
            }
        };

        if params.sanity_check && rw_counter > params.rw_counter_max {
            panic!("rw_counter out of range");
        }
        let rw_counter = {
            let field_elem = F::from(rw_counter as u64);

            let cell = region.assign_advice(
                || "rw_counter",
                self.rw_counter,
                offset,
                || Ok(field_elem),
            )?;

            Variable::<usize, F> {
                cell,
                field_elem: Some(field_elem),
                value: Some(rw_counter),
            }
        };

        let value = {
            let cell = region.assign_advice(|| "value", self.value, offset, || Ok(value))?;

            Variable::<F, F> {
                cell,
                field_elem: Some(value),
                value: Some(value),
            }
        };

        let storage_key = {
            let cell = region.assign_advice(
                || "storage key",
                self.storage_key,
                offset,
                || Ok(storage_key),
            )?;

            Variable::<F, F> {
                cell,
                field_elem: Some(storage_key),
                value: Some(storage_key),
            }
        };

        let value_prev = {
            let cell = region.assign_advice(
                || "value prev",
                self.value_prev,
                offset,
                || Ok(value_prev),
            )?;

            Variable::<F, F> {
                cell,
                field_elem: Some(value_prev),
                value: Some(value_prev),
            }
        };

        let flag_write = {
            let field_elem = F::from(flag_write as u64);
            let cell = region.assign_advice(
                || "flag_write",
                self.flag_write,
                offset,
                || Ok(field_elem),
            )?;

            Variable::<bool, F> {
                cell,
                field_elem: Some(field_elem),
                value: Some(flag_write),
            }
        };

        let tag = {
            let value = Some(tag);
            let field_elem = Some(F::from(tag as u64));
            let cell =
                region.assign_fixed(|| "tag", self.tag, offset, || Ok(F::from(tag as u64)))?;
            Variable::<usize, F> {
                cell,
                field_elem,
                value,
            }
        };

        Ok(BusMapping {
            rw_counter,
            tag,
            flag_write,
            address,
            value,
            storage_key,
            value_prev,
        })
    }
}

/// State Circuit struct.
#[derive(Default)]
pub struct StateCircuit<
    F: FieldExt,
    const MEMORY_ADDRESS_MAX: usize,
    const STACK_ADDRESS_MAX: usize,
> {
    pub params: StateCircuitParams,
    /// randomness used in linear combination
    pub randomness: F,
    /// Memory Operations
    pub memory_ops: Vec<Operation<MemoryOp>>,
    /// Stack Operations
    pub stack_ops: Vec<Operation<StackOp>>,
    /// Storage Operations
    pub storage_ops: Vec<Operation<StorageOp>>,
}

impl<F: FieldExt, const MEMORY_ADDRESS_MAX: usize, const STACK_ADDRESS_MAX: usize>
    StateCircuit<F, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX>
{
    /// Use memory_ops, stack_ops, storage_ops to build a StateCircuit instance.
    pub fn new(
        params: StateCircuitParams,
        randomness: F,
        memory_ops: Vec<Operation<MemoryOp>>,
        stack_ops: Vec<Operation<StackOp>>,
        storage_ops: Vec<Operation<StorageOp>>,
    ) -> Self {
        Self {
            params,
            randomness,
            memory_ops,
            stack_ops,
            storage_ops,
        }
    }
}

impl<F: FieldExt, const MEMORY_ADDRESS_MAX: usize, const STACK_ADDRESS_MAX: usize> Circuit<F>
    for StateCircuit<F, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX>
{
    type Config = Config<F, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load(&self.params, &mut layouter)?;
        config.assign(
            &self.params,
            layouter,
            self.randomness,
            self.memory_ops.clone(),
            self.stack_ops.clone(),
            self.storage_ops.clone(),
        )?;

        Ok(())
    }
}
#[cfg(test)]
mod state_circuit_tests {
    use super::*;
    use bus_mapping::operation::{MemoryOp, Operation, RWCounter, StackOp, StorageOp, RW};
    use eth_types::evm_types::{MemoryAddress, StackAddress};
    use eth_types::{address, bytecode, Word};
    use halo2::arithmetic::BaseExt;
    use halo2::dev::{MockProver, VerifyFailure::ConstraintNotSatisfied, VerifyFailure::Lookup};
    use pairing::bn256::Fr;

    macro_rules! test_state_circuit {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr, $result:expr) => {{
            let params = StateCircuitParams {
                sanity_check: true,
                rw_counter_max: $rw_counter_max,
                memory_rows_max: $memory_rows_max,
                memory_address_max: $memory_address_max,
                stack_rows_max: $stack_rows_max,
                stack_address_max: $stack_address_max,
                storage_rows_max: $storage_rows_max,
            };
            let circuit = StateCircuit::<Fr, $memory_address_max, $stack_address_max> {
                params,
                randomness: Fr::rand(),
                memory_ops: $memory_ops,
                stack_ops: $stack_ops,
                storage_ops: $storage_ops,
            };

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    macro_rules! test_state_circuit_error {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr) => {{
            let params = StateCircuitParams {
                sanity_check: false,
                rw_counter_max: $rw_counter_max,
                memory_rows_max: $memory_rows_max,
                memory_address_max: $memory_address_max,
                stack_rows_max: $stack_rows_max,
                stack_address_max: $stack_address_max,
                storage_rows_max: $storage_rows_max,
            };
            let circuit = StateCircuit::<Fr, $memory_address_max, $stack_address_max> {
                params,
                randomness: Fr::rand(),
                memory_ops: $memory_ops,
                stack_ops: $stack_ops,
                storage_ops: $storage_ops,
            };

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    fn constraint_not_satisfied(
        row: usize,
        gate_index: usize,
        gate_name: &'static str,
        index: usize,
    ) -> halo2::dev::VerifyFailure {
        ConstraintNotSatisfied {
            constraint: ((gate_index, gate_name).into(), index, "").into(),
            row,
            cell_values: vec![],
        }
    }

    fn lookup_fail(row: usize, lookup_index: usize) -> halo2::dev::VerifyFailure {
        Lookup { lookup_index, row }
    }

    #[test]
    fn state_circuit() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            StackOp::new(RW::WRITE, 1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            StackOp::new(RW::READ, 1, StackAddress::from(1), Word::from(32)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(17),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
            ),
        );

        test_state_circuit!(
            14,
            2000,
            100,
            2,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![storage_op_0, storage_op_1, storage_op_2],
            Ok(())
        );
    }

    #[test]
    fn no_stack_padding() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            StackOp::new(RW::WRITE, 1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            StackOp::new(RW::READ, 1, StackAddress::from(1), Word::from(32)),
        );

        const STACK_ROWS_MAX: usize = 2;
        test_state_circuit!(
            14,
            2000,
            100,
            STACK_ROWS_MAX,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![],
            Ok(())
        );
    }

    #[test]
    fn same_address_read() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 31),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            MemoryOp::new(
                RW::READ,
                1,
                MemoryAddress::from(0),
                32,
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(19),
            StackOp::new(RW::WRITE, 1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(28),
            StackOp::new(
                RW::READ,
                1,
                StackAddress::from(0),
                Word::from(13),
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        const MEMORY_ROWS_MAX: usize = 7;
        test_state_circuit_error!(
            14,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn first_write() {
        let stack_op_0 = Operation::new(
            RWCounter::from(28),
            StackOp::new(RW::READ, 1, StackAddress::from(0), Word::from(13)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(17),
            StorageOp::new(
                RW::READ, /* Fails because the first storage op needs to be
                           * write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            StorageOp::new(
                RW::READ, /* Fails because when storage key changes, the op
                           * needs to be write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::from(0),
            ),
        );

        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            StorageOp::new(
                RW::READ, /* Fails because when address changes, the op
                           * needs to be write. */
                address!("0x0000000000000000000000000000000000000003"),
                Word::from(0x40),
                /* Intentionally different storage key as the last one in the previous ops to
                have two conditions met. */
                Word::from(32),
                Word::from(0),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            14,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![stack_op_0],
            vec![storage_op_0, storage_op_1, storage_op_2]
        );
    }

    #[test]
    fn max_values() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_2 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );

        let memory_op_3 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(
                RW::WRITE,
                1,
                MemoryAddress::from(MEMORY_ADDRESS_MAX + 1),
                32,
            ),
        );
        let memory_op_4 = Operation::new(
            RWCounter::from(24),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(MEMORY_ADDRESS_MAX + 1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            StackOp::new(
                RW::WRITE,
                1,
                StackAddress::from(STACK_ADDRESS_MAX),
                Word::from(12),
            ),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            StackOp::new(
                RW::READ,
                1,
                StackAddress::from(STACK_ADDRESS_MAX),
                Word::from(12),
            ),
        );

        let stack_op_2 = Operation::new(
            RWCounter::from(17),
            StackOp::new(
                RW::WRITE,
                1,
                StackAddress::from(STACK_ADDRESS_MAX + 1),
                Word::from(12),
            ),
        );
        let stack_op_3 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            StackOp::new(
                RW::WRITE,
                1,
                StackAddress::from(STACK_ADDRESS_MAX + 1),
                Word::from(12),
            ),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 7;
        const STACK_ROWS_MAX: usize = 7;
        const STORAGE_ROWS_MAX: usize = 7;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            16,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![
                memory_op_0,
                memory_op_1,
                memory_op_2,
                memory_op_3,
                memory_op_4
            ],
            vec![stack_op_0, stack_op_1, stack_op_2, stack_op_3],
            vec![]
        );
    }

    #[test]
    fn max_values_first_row() {
        // first row of a tag needs to be checked for address to be in range
        // too
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            MemoryOp::new(
                RW::WRITE,
                1,
                MemoryAddress::from(MEMORY_ADDRESS_MAX + 1),
                // This address is not in the allowed range
                32,
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            StackOp::new(
                RW::WRITE,
                1,
                StackAddress::from(STACK_ADDRESS_MAX + 1),
                Word::from(12),
            ),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            StackOp::new(
                RW::READ,
                1,
                StackAddress::from(STACK_ADDRESS_MAX + 1),
                Word::from(12),
            ),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 2;
        const STACK_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            16,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![memory_op_0],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn non_monotone_rw_counter() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            MemoryOp::new(RW::READ, 1, MemoryAddress::from(0), 32),
        );

        // fails because it needs to be strictly monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            StackOp::new(RW::WRITE, 1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(217),
            StackOp::new(RW::READ, 1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(217),
            StackOp::new(RW::READ, 1, StackAddress::from(1), Word::from(12)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(301),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(302),
            StorageOp::new(
                RW::READ,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(302),
            StorageOp::new(
                RW::READ,
                /*fails because the address and
                 * storage key are the same as in
                 * the previous row */
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(297),
            StorageOp::new(
                RW::WRITE,
                // rw_counter goes down, but it doesn't fail because
                // the storage key is not the same as in the previous row.
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x41),
                Word::from(32),
                Word::from(32),
            ),
        );

        let storage_op_4 = Operation::new(
            RWCounter::from(296),
            StorageOp::new(
                RW::WRITE,
                // rw_counter goes down, but it doesn't fail because the
                // address is not the same as in the previous row (while the
                // storage key is).
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::from(0),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 100;
        const STACK_ROWS_MAX: usize = 100;
        test_state_circuit_error!(
            15,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            STACK_ROWS_MAX,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![
                storage_op_0,
                storage_op_1,
                storage_op_2,
                storage_op_3,
                storage_op_4
            ]
        );
    }

    #[test]
    fn non_monotone_address() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(1), 32),
        );

        // fails because it's not monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            MemoryOp::new(RW::WRITE, 1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            StackOp::new(RW::WRITE, 1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(229),
            StackOp::new(RW::WRITE, 1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(230),
            StackOp::new(
                RW::WRITE,
                1,
                StackAddress::from(0), /* this fails because the
                                        * address is not
                                        * monotone */
                Word::from(12),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 10;
        test_state_circuit_error!(
            14,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            10,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![]
        );
    }

    #[test]
    fn storage() {
        let storage_op_0 = Operation::new(
            RWCounter::from(18),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(19),
            StorageOp::new(
                RW::READ,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(33), /* Fails because it is READ op
                                 * and not the same
                                 * value as in the previous
                                 * row. */
                Word::from(0),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(20),
            StorageOp::new(
                RW::WRITE,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0), /* Fails because not the same
                                * as value in the previous row - note: this
                                * is WRITE. */
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(21),
            StorageOp::new(
                RW::READ,
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(1), /* Fails because not the same
                                * as value_prev in the previous row - note:
                                * this is READ. */
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            14,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![],
            vec![storage_op_0, storage_op_1, storage_op_2, storage_op_3]
        );
    }

    #[test]
    fn trace() {
        let bytecode = bytecode! {
            PUSH1(0x80)
            PUSH1(0x40)
            MSTORE
            #[start]
            PUSH1(0x40)
            MLOAD
            STOP
        };
        let block = bus_mapping::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code_at_start(&bytecode).unwrap(),
        );
        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let stack_ops = builder.block.container.sorted_stack();

        test_state_circuit!(
            14,
            2000,
            100,
            2,
            100,
            1023,
            1000,
            vec![],
            stack_ops,
            vec![],
            Ok(())
        );
    }
}
