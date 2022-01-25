use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

use crate::gates::base_conversion::BaseConversionConfig;
use crate::gates::tables::BaseInfo;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub(crate) struct StateBaseConversion<F> {
    bi: BaseInfo<F>,
    bccs: [BaseConversionConfig<F>; 25],
    state: [Column<Advice>; 25],
}

impl<F: FieldExt> StateBaseConversion<F> {
    /// Side effect: parent flag is enabled
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
        bi: BaseInfo<F>,
        flag: Column<Advice>,
    ) -> Self {
        meta.enable_equality(flag.into());
        let bccs: [BaseConversionConfig<F>; 25] = state
            .iter()
            .map(|&lane| {
                BaseConversionConfig::configure(meta, bi.clone(), lane, flag)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { bi, bccs, state }
    }

    pub(crate) fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        state: [(Cell, F); 25],
        flag: (Cell, F),
    ) -> Result<[(Cell, F); 25], Error> {
        let state: Result<Vec<(Cell, F)>, Error> = state
            .iter()
            .zip(self.bccs.iter())
            .map(|(&lane, config)| {
                let output = config.assign_region(layouter, lane, flag)?;
                Ok(output)
            })
            .into_iter()
            .collect();
        let state = state?;
        let state: [(Cell, F); 25] = state.try_into().unwrap();
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith_helpers::{convert_b9_coef, convert_lane};
    use crate::gates::{
        gate_helpers::biguint_to_f,
        tables::{FromBase9TableConfig, FromBinaryTableConfig},
    };
    use halo2::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use num_bigint::BigUint;
    use pairing::arithmetic::FieldExt;
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_state_base_conversion() {
        // We have to use a MyConfig because:
        // We need to load the table
        #[derive(Debug, Clone)]
        struct MyConfig<F> {
            flag: Column<Advice>,
            state: [Column<Advice>; 25],
            table: FromBase9TableConfig<F>,
            conversion: StateBaseConversion<F>,
        }
        impl<F: FieldExt> MyConfig<F> {
            pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
                let table = FromBase9TableConfig::configure(meta);
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| meta.advice_column())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let flag = meta.advice_column();
                let bi = table.get_base_info(false);
                let conversion =
                    StateBaseConversion::configure(meta, state, bi, flag);
                Self {
                    flag,
                    state,
                    table,
                    conversion,
                }
            }

            pub fn load(
                &self,
                layouter: &mut impl Layouter<F>,
            ) -> Result<(), Error> {
                self.table.load(layouter)
            }

            pub fn assign_region(
                &self,
                layouter: &mut impl Layouter<F>,
                input: [F; 25],
            ) -> Result<[F; 25], Error> {
                let flag_value = F::one();
                let (state, flag) = layouter.assign_region(
                    || "Input state",
                    |mut region| {
                        let state: [(Cell, F); 25] = input
                            .iter()
                            .enumerate()
                            .map(|(idx, &value)| {
                                let cell = region
                                    .assign_advice(
                                        || format!("State {}", idx),
                                        self.state[idx],
                                        0,
                                        || Ok(value),
                                    )
                                    .unwrap();
                                (cell, value)
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
                        let flag = region.assign_advice(
                            || "Flag",
                            self.flag,
                            0,
                            || Ok(flag_value),
                        )?;
                        Ok((state, flag))
                    },
                )?;
                let output_state = self.conversion.assign_region(
                    layouter,
                    state,
                    (flag, flag_value),
                )?;
                let output_state: [F; 25] = output_state
                    .iter()
                    .map(|&(_, value)| value)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Ok(output_state)
            }
        }

        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                Self::Config::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.load(&mut layouter)?;
                let out_state =
                    config.assign_region(&mut layouter, self.in_state)?;
                assert_eq!(out_state, self.out_state);
                Ok(())
            }
        }
        let in_state_flat: [BigUint;25] = [
            BigUint::parse_bytes(b"0000000000000002939a42ef593e37757abe328e9e409e75dcd76cf1b3427bc3", 16).unwrap(),
            BigUint::parse_bytes(b"0000000000000017304eb2ce92f928242022ad262628dc849adb625f6b968a37", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000000000000120d25d0f56593ca22c972e492ebee2df2437baeb99", 16).unwrap(),
            BigUint::parse_bytes(b"0000000000000000094572b32ec9365d255a21fb433f40ac5b99c7e4cebb8cb9", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000001a16689ee95290209b9c798319f001f9f47b48869c2e205d86e", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000004ab8206bfe1fba3cce85f5adc5d0cf96e8f3339ed5d0e37918", 16).unwrap(),
            BigUint::parse_bytes(b"0000000000000073f1df47690dc94fcbd6741ee5a051f2351b72f6000f0331f5", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000000000001d5f9b28cfc0b2c50c83057db86bfb5769003f902037", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000004e39a67e78cbf85de840f7c95b7742d36c51555fc2cca1a439", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000002721a9cc97e014fc3489a0eda1ccdfb0d04f2f767b50a0277b7", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000180c3458274a720821b04bb6ea89a4ad156c10ce10cbdc24bb", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000005cc157639d977ffdf744eaad888c1229bad0957ce32ec0da85", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000027230bac73a5243d6da0e3131d993321f2036cbedf4f58dc300", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000001a285417c116f2ac34f96967b74e3a110840e0215d54e6fab2", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000d0b2de05776e78c61e9830400d9b237381a5ad8673ffa39e72", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000002ea9e9eb519f00f4df320dc39b724f4d2c4345b9ce5694ad72", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000004591254961e3709c02675d21d2736af9c1058a4bdcea648e0c", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000d0bae8fc241887f8663b3cfc24bbb944db8e6395c93f344b5e", 16).unwrap(),
            BigUint::parse_bytes(b"000000000000003423c0b28aebc76f619d18104607321b035bc33c2ca938c191", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000004137e08e5d5765ea5818581d9b8c28b667015c6a175f85722a6", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000084d6779f4dd2135f166692db6840c505a168d7c9a9b01e6f6", 16).unwrap(),
            BigUint::parse_bytes(b"0000000000000073f1897de594b15c2d566201d330a37ce1ff42011d3e16dbe1", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000001a175d1d782a3395639e06c37c5137a23ca612b75daaad96bd6", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000002d59ded6d71ae39b5ddb65100d3c009abe2e7ab7a69a5d53", 16).unwrap(),
            BigUint::parse_bytes(b"00000000000000d0b5c85eb77ac4120ba8de268314a3297a7d4ecfa9550e44ef", 16).unwrap(),
        ];

        for (idx, x) in in_state_flat.iter().enumerate() {
            assert!(x.lt(&BigUint::from(9 as u64).pow(64)));
            let lane_b13 = convert_lane(x.clone(), 9, 13, convert_b9_coef);
            assert!(
                lane_b13.lt(&BigUint::from(13 as u64).pow(64)),
                "idx {}, lane {:?}",
                idx,
                lane_b13
            );
            if idx == 0 {
                let v = lane_b13.to_radix_be(13);
                println!("outstate 0 expect len {} b13be {:?}", v.len(), v)
            }
        }
        let v = BigUint::parse_bytes(
            b"0000000000000c63d4799166557f489bd0c58fd5d570fbd9d7ae3522582d02bf",
            16,
        )
        .unwrap()
        .to_radix_be(13);
        println!("outstate 0 circuit len {} b13be {:?}", v.len(), v);

        let in_state: [Fp; 25] = in_state_flat
            .iter()
            .map(|x| biguint_to_f(x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let out_state: [Fp; 25] = in_state_flat
            .iter()
            .map(|x| {
                biguint_to_f::<Fp>(&convert_lane(
                    x.clone(),
                    9,
                    13,
                    convert_b9_coef,
                ))
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let circuit = MyCircuit::<Fp> {
            in_state,
            out_state,
        };
        let prover = MockProver::<Fp>::run(17, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
