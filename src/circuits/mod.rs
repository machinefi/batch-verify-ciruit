use halo2_curves::{bn256::{Fq as BnBase, Fr as BnScalar}, ff::{PrimeField, WithSmallOrderMulGroup}, secp256k1::{Fp as SecpBase, Fq as SecpScalar}};
pub mod ecdsa;
pub mod ecc;
pub mod integer;
pub mod maingate;
pub mod halo2wrong;

// pub trait FieldExt: PrimeField + WithSmallOrderMulGroup<3> {}
// pub trait FieldExt: WithSmallOrderMulGroup<3> + Ord {}
// pub trait FieldScalar: PrimeField {}
// // impl FieldExt for <Secp256k1Affine as CurveAffine>::ScalarExt {}
// impl FieldExt for BnBase {}
// impl FieldExt for BnScalar {}
// impl FieldExt for SecpBase {}
// impl FieldExt for SecpScalar {}