use crate::arith_helpers::*;
use crate::common::*;
use crate::gates::gate_helpers::biguint_to_f;
use crate::keccak_arith::*;
use halo2::circuit::Cell;
use halo2::circuit::Layouter;
use halo2::{
    circuit::Region,
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct IotaB9Config<F> {
    q_normal_round: Selector,
    q_last_round: Selector,
    lane: Column<Advice>,
    flag_is_mixing: Column<Advice>,
    /// round constant in base 9
    pub(crate) rc_b9_mul_a4: Column<Fixed>,
    /// pre-computed round constant in base 9
    all_rc_b9_mul_a4: [F; PERMUTATION],
}

impl<F: FieldExt> IotaB9Config<F> {
    // We assume state is recieved in base-9.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state_00: Column<Advice>,
        // only passed in the final round
        flag_is_mixing: Option<Column<Advice>>,
    ) -> Self {
        // The main purpose is to copy state_00
        meta.enable_equality(state_00.into());
        if let Some(flag_is_mixing) = flag_is_mixing {
            meta.enable_equality(flag_is_mixing.into());
        }

        let q_normal_round = meta.selector();
        let q_last_round = meta.selector();
        let lane = meta.advice_column();
        let rc_b9_mul_a4 = meta.fixed_column();
        // enabled when not mixing
        let flag_is_mixing = meta.advice_column();

        // def iota_b9(state: List[List[int], round_constant_base9: int):
        //     d = round_constant_base9
        //     # state[0][0] has 2*a + b + 3*c already, now add 2*d to make it
        // 2*a + b + 3*c + 2*d     # coefficient in 0~8
        //     state[0][0] += 2*d
        //     return state
        meta.create_gate("iota_b9", |meta| {
            let q_normal_round = meta.query_selector(q_normal_round);
            let q_last_round = meta.query_selector(q_last_round);
            let is_not_mixing = Expression::Constant(F::one())
                - meta.query_advice(flag_is_mixing, Rotation::cur());
            let rc_b9_mul_a4 = meta.query_fixed(rc_b9_mul_a4, Rotation::cur());
            let next_lane = meta.query_advice(lane, Rotation::next());
            let lane = meta.query_advice(lane, Rotation::cur());
            let check_poly = lane + rc_b9_mul_a4 - next_lane;
            vec![
                q_normal_round * check_poly,
                q_last_round * is_not_mixing * check_poly,
            ]
        });

        let all_rc_b9_mul_a4 = ROUND_CONSTANTS
            .iter()
            .map(|&r| biguint_to_f::<F>(&(convert_b2_to_b9(r) * A4)))
            .collect_vec()
            .try_into()
            .unwrap();

        Self {
            q_normal_round,
            q_last_round,
            lane,
            flag_is_mixing,
            rc_b9_mul_a4,
            all_rc_b9_mul_a4,
        }
    }

    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        round: usize,
        is_mixing: Option<(Cell, F)>,
    ) -> Result<[(Cell, F); 25], Error> {
        // do nothing on the state_rest, just send them back to the output
        let (state_00, state_rest) = in_state.split_first().unwrap();

        let new_state_00 = layouter.assign_region(
            || format!("iota_b9 round {}", round),
            |mut region| {
                let mut offset = 0;
                if round != PERMUTATION - 1 {
                    self.q_normal_round.enable(&mut region, offset)?;
                } else {
                    self.q_last_round.enable(&mut region, offset)?;
                }
                let lane = {
                    let value = state_00.1;
                    let cell = region.assign_advice(
                        || "lane",
                        self.lane,
                        offset,
                        || Ok(value),
                    )?;
                    region.constrain_equal(state_00.0, cell)?;
                    (cell, value)
                };
                let rc_b9_mul_a4 = {
                    let value = self.all_rc_b9_mul_a4[round];
                    let cell = region.assign_fixed(
                        || "round constant * A4",
                        self.rc_b9_mul_a4,
                        offset,
                        || Ok(value),
                    )?;
                    (cell, value)
                };
                if let Some(is_mixing) = is_mixing {
                    let cell = region.assign_advice(
                        || format!("assign is_mixing flag {:?}", is_mixing.1),
                        self.flag_is_mixing,
                        offset,
                        || Ok(is_mixing.1),
                    )?;
                    region.constrain_equal(is_mixing.0, cell)?;
                };

                offset += 1;
                let next_lane = {
                    let value = lane.1 + rc_b9_mul_a4.1;
                    let cell = region.assign_advice(
                        || "next lane",
                        self.lane,
                        offset,
                        || Ok(value),
                    )?;
                    (cell, value)
                };

                Ok(next_lane)
            },
        )?;

        // join the state00 with the rest of the state
        let out_state: [(Cell, F); 25] = vec![new_state_00]
            .iter()
            .chain((*state_rest).iter())
            .map(|&x| x)
            .collect_vec()
            .try_into()
            .unwrap();
        Ok(out_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{PERMUTATION, ROUND_CONSTANTS};
    use crate::gates::gate_helpers::biguint_to_f;
    use halo2::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_iota_b9_gate_last_round() {
        #[derive(Clone)]
        struct MyConfig<F> {
            state: [Column<Advice>; 25],
            is_mixing: Column<Advice>,
            iota_b9: IotaB9Config<F>,
        }

        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            // This usize is indeed pointing the exact row of the
            // ROUND_CTANTS_B9 we want to use.
            round: usize,
            // The flag acts like a selector that turns ON/OFF the gate
            flag: bool,
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column.into());
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let is_mixing = meta.advice_column();
                let iota_b9 =
                    IotaB9Config::configure(meta, state[0], Some(is_mixing));

                Self::Config {
                    state,
                    is_mixing,
                    iota_b9,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let (in_state, is_mixing) = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
                        let offset = 0;
                        let is_mixing = {
                            let val: F = (self.flag as u64).into();
                            let cell = region.assign_advice(
                                || "witness is_mixing",
                                config.is_mixing,
                                offset,
                                || Ok(val),
                            )?;
                            (cell, val)
                        };

                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> =
                                Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };
                        Ok((in_state, is_mixing))
                    },
                )?;

                // Assign `in_state`, `out_state`, round and flag
                config.iota_b9.assign_region(
                    &mut layouter,
                    in_state,
                    self.round,
                    Some(is_mixing),
                )?;
                Ok(())
            }
        }

        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];
        let (in_state, out_state) =
            IotaB9Config::compute_circ_states(input1.into());

        let constants: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // (flag = 0) -> Out state is checked as constraints are applied.
        // Providing the correct `out_state` should pass the verification.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                round_ctant: PERMUTATION - 1,
                flag: false,
                _marker: PhantomData,
            };

            let prover =
                MockProver::<Fp>::run(9, &circuit, vec![constants.clone()])
                    .unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }

        // (flag = 0) -> Out state is checked as constraints are applied.
        // Providing the wrong `out_state` should make the verification fail.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                // Add wrong out_state that should cause the verification to
                // fail.
                out_state: in_state,
                round_ctant: PERMUTATION - 1,
                flag: false,
                _marker: PhantomData,
            };

            let prover =
                MockProver::<Fp>::run(9, &circuit, vec![constants.clone()])
                    .unwrap();

            let _ = prover.verify().is_err();
        }

        // (flag = 1)
        let circuit = MyCircuit::<Fp> {
            in_state,
            // Use a nonsensical out_state to verify that the gate is not
            // checked.
            out_state: in_state,
            round_ctant: PERMUTATION - 1,
            flag: true,
            _marker: PhantomData,
        };

        let prover =
            MockProver::<Fp>::run(9, &circuit, vec![constants]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_iota_b9_gate_not_last_round() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            round_ctant_b9: usize,
            _marker: PhantomData<F>,
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = IotaB9Config<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column.into());
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let round_ctant_b9 = meta.advice_column();
                // Allocate space for the round constants in base-9 which is an
                // instance column
                let round_ctants = meta.instance_column();

                IotaB9Config::configure(
                    meta,
                    state,
                    round_ctant_b9,
                    round_ctants,
                )
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let in_state = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
                        let offset: usize = 0;

                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> =
                                Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };
                        Ok(in_state)
                    },
                )?;

                // Start IotaB9 config without copy at offset = 0
                config.not_last_round(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.round_ctant_b9,
                )?;

                Ok(())
            }
        }

        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];
        let mut in_biguint = StateBigInt::default();
        let mut in_state: [Fp; 25] = [Fp::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] = convert_b2_to_b9(input1[x][y]);
            in_state[5 * x + y] = biguint_to_f(&in_biguint[(x, y)]);
        }

        // Test for the 25 rounds
        for (round_idx, round_val) in
            ROUND_CONSTANTS.iter().enumerate().take(PERMUTATION)
        {
            // Compute out state
            let s1_arith = KeccakFArith::iota_b9(&in_biguint, *round_val);
            let out_state = state_bigint_to_field::<Fp, 25>(s1_arith);

            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                round_ctant_b9: round_idx,
                _marker: PhantomData,
            };

            let constants: Vec<Fp> = ROUND_CONSTANTS
                .iter()
                .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
                .collect();

            let prover =
                MockProver::<Fp>::run(9, &circuit, vec![constants]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
