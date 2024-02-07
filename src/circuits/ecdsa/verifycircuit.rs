use std::ops::Add;
use std::{marker::PhantomData, ops::Mul};

use group::ff::Field;
use group::Curve;
use group::prime::PrimeCurveAffine;
use halo2_proofs::{circuit::{Layouter, SimpleFloorPlanner}, halo2curves::{CurveAffine, CurveExt}, plonk::{Circuit, ConstraintSystem, Error}};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use pasta_curves::arithmetic::FieldExt;

use crate::circuits::halo2wrong::utils::{big_to_fe, fe_to_big};
use crate::circuits::{ecc::{EccConfig, GeneralEccChip}, halo2wrong::RegionCtx, integer::{AssignedInteger, IntegerInstructions, Range, NUMBER_OF_LOOKUP_LIMBS}, maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions}};

use super::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};



// use super::AssignedEcdsaStarSig;
// use ecc::maingate::big_to_fe;
// use ecc::maingate::fe_to_big;

// use halo2::arithmetic::CurveAffine;
// use halo2::arithmetic::FieldExt;
// use halo2::dev::MockProver;
// use num_bigint::BigUint;
// use rand_core::OsRng;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

#[derive(Clone, Debug)]
pub struct CircuitEcdsaVerifyConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl CircuitEcdsaVerifyConfig {
    pub fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
        let (rns_base, rns_scalar) =
            GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<N>::configure(meta);
        let mut overflow_bit_lengths: Vec<usize> = vec![];
        overflow_bit_lengths.extend(rns_base.overflow_lengths());
        overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
        let range_config =
            RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
        CircuitEcdsaVerifyConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub fn config_range<N: FieldExt>(
        &self,
        layouter: &mut impl Layouter<N>,
    ) -> Result<(), Error> {
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
        range_chip.load_limb_range_table(layouter)?;
        range_chip.load_overflow_range_tables(layouter)?;

        Ok(())
    }
}

#[derive(Default, Clone)]
struct BatchEcdsaVerifyInput<E: CurveAffine> {
    pk: Vec<E>,
    m_hash: Vec<E::Scalar>,
    s: Vec<E::Scalar>,
    r: Vec<E::Scalar>,
}

impl<E: CurveAffine> BatchEcdsaVerifyInput<E> {
    fn new() -> Self {
        Self {
            pk: vec![],
            m_hash: vec![],
            r: vec![],
            s: vec![],
        }
    }
}

#[derive(Default, Clone)]
pub struct IntegratedCircuit<E: CurveAffine, N: FieldExt> {
    pub aux_generator: E,
    pub window_size: usize,
    pub batch_size: usize,
    pub _marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt> Circuit<N> for IntegratedCircuit<E, N> {
    type Config = CircuitEcdsaVerifyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        CircuitEcdsaVerifyConfig::new::<E, N>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            config.ecc_chip_config(),
        );
        let scalar_chip = ecc_chip.scalar_field_chip();

        let mut rng = thread_rng();

        let mut bevi = BatchEcdsaVerifyInput::<E>::new();
        // generate a batch of valid signatures
        let generator = <E as PrimeCurveAffine>::generator();
        for _ in 0..self.batch_size {
            // Generate a key pair
            let sk = <E as CurveAffine>::ScalarExt::random(&mut rng);
            let pk: E = (generator * sk).to_affine();
            println!("pk {:?}", pk);

            // Generate a valid_hash
            let m_hash = <E as CurveAffine>::ScalarExt::random(&mut rng);
            println!("m_hash {:?}", m_hash);

            let mut hasher = Sha256::new();
            hasher.update(b"TEST");
            let result = hasher.finalize();
            let result_str = hex::encode(result);
            println!("Hash: {}", result_str);

            // let s = &result_str[2..];
            let mut bytes = hex::decode(&result_str).expect("Invalid params");
            bytes.reverse();
            let mut bytes_wide: [u8; 64] = [0; 64];
            bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);

            // let result_bytes = result.to_vec();
            // let big_int = BigUint::from_bytes_be(&result_bytes);
            let m_hash = <E as CurveAffine>::ScalarExt::from_bytes_wide(&bytes_wide);

            let randomness = <E as CurveAffine>::ScalarExt::random(&mut rng);
            let randomness_inv = randomness.invert().unwrap();

            // Compute `r`
            let r_point = (generator * randomness).to_affine().coordinates().unwrap();
            let x = r_point.x();
            let r = mod_n::<E>(*x);

            // Compute `s`
            let s: <<<E as CurveAffine>::CurveExt as CurveExt>::ScalarExt as Mul<<<<E as CurveAffine>::CurveExt as CurveExt>::ScalarExt as Add<<<E as CurveAffine>::ScalarExt as Mul<<<E as CurveAffine>::CurveExt as CurveExt>::ScalarExt>>::Output>>::Output>>::Output = randomness_inv * (m_hash + r * sk);

            println!("r {:?}", r);
            println!("s {:?}", s);

            let r = "e5aabbe30f3ef400e04ee26aef767a30e453e0362bd097b6ee366ff75409f332";
            let s = "629c91d92aef44c43125b04b88b804f007247de63b5ec9cd037fed1d44cfb010";
            let mut bytes = hex::decode(&r).expect("Invalid params");
            bytes.reverse();
            let mut bytes_wide: [u8; 64] = [0; 64];
            bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
            let r = <E as CurveAffine>::ScalarExt::from_bytes_wide(&bytes_wide);


            let mut bytes = hex::decode(&s).expect("Invalid params");
            bytes.reverse();
            let mut bytes_wide: [u8; 64] = [0; 64];
            bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
            let s = <E as CurveAffine>::ScalarExt::from_bytes_wide(&bytes_wide);

            // pk (0x8259855a1fd72f8170346cbcc2f6562b985ba7c4438968bea268d809e6189688, 0x38e9f99831a7a8590a692598a5b3a5999c44cd5557e5e926e682325dd1787414)
            let x = "8259855a1fd72f8170346cbcc2f6562b985ba7c4438968bea268d809e6189688";
            let y = "38e9f99831a7a8590a692598a5b3a5999c44cd5557e5e926e682325dd1787414";
            let mut bytes = hex::decode(&x).expect("Invalid params");
            bytes.reverse();
            let mut bytes_wide: [u8; 64] = [0; 64];
            bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
            let x = <E as CurveAffine>::Base::from_bytes_wide(&bytes_wide);


            let mut bytes = hex::decode(&y).expect("Invalid params");
            bytes.reverse();
            let mut bytes_wide: [u8; 64] = [0; 64];
            bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
            let y = <E as CurveAffine>::Base::from_bytes_wide(&bytes_wide);

            let pk = <E as CurveAffine>::from_xy(x, y).unwrap();

            bevi.pk.push(pk);
            bevi.m_hash.push(m_hash);
            bevi.r.push(r);
            bevi.s.push(s);
        }

        layouter.assign_region(
            || "assign aux values",
            |mut region| {
                let offset = &mut 0;
                let ctx = &mut RegionCtx::new(&mut region, offset);

                ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                ecc_chip.assign_aux(ctx, self.window_size, 2)?;
                Ok(())
            },
        )?;

        let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
        layouter
            .assign_region(
                || "region 0",
                |mut region| {
                    let mut assigned_bevi: Vec<(
                        AssignedPublicKey<E::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                        AssignedEcdsaSig<E::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                        AssignedInteger<E::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                    )> = Vec::with_capacity(self.batch_size);
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    for i in 0..self.batch_size {
                        let integer_r = ecc_chip.new_unassigned_scalar(Some(bevi.r[i]));
                        let integer_s = ecc_chip.new_unassigned_scalar(Some(bevi.s[i]));
                        let msg_hash = ecc_chip.new_unassigned_scalar(Some(bevi.m_hash[i]));

                        let r_assigned =
                            scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
                        let s_assigned =
                            scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
                        let sig = AssignedEcdsaSig {
                            r: r_assigned,
                            s: s_assigned,
                        };

                        let pk_in_circuit =
                            ecc_chip.assign_point(ctx, Some(bevi.pk[i].into()))?;
                        let pk_assigned = AssignedPublicKey {
                            point: pk_in_circuit,
                        };
                        let msg_hash =
                            scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                        assigned_bevi.push((pk_assigned, sig, msg_hash));
                    }

                    ecdsa_chip.batch_verify(ctx, assigned_bevi).unwrap();
                    Ok(())
                },
            )
            .unwrap();
        config.config_range(&mut layouter)?;

        Ok(())
    }
}