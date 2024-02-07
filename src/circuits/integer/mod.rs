//! `integer` implements constraints for non native field
//! operations

#![feature(trait_alias)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]


use crate::circuits::integer::rns::{Common, Integer, Limb};
use halo2_curves::ff::WithSmallOrderMulGroup as FieldExt;
use halo2_proofs::circuit::Cell;
use crate::circuits::maingate::{big_to_fe, compose, fe_to_big, Assigned, AssignedValue, UnassignedValue};
use num_bigint::BigUint as big_uint;
use rns::Rns;
use std::rc::Rc;

pub use chip::{IntegerChip, IntegerConfig};
pub use instructions::{IntegerInstructions, Range};
// pub use maingate;
// pub use crate::circuits::halo2wrong::halo2;

#[cfg(test)]
use halo2_curves as curves;



/// Chip for integer constaints
pub mod chip;
/// Commoon instructions for integer operations and assignments
pub mod instructions;
/// Residue number system construction and utilities
pub mod rns;

/// `RangeChip` supports upto four full limbs decomposition of a value
/// `AssignedLimb` is mostly subjected to the range check. Say we have 68-bit
/// limb and it is decomposed to four 17-bit limbs.
pub const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

/// AssignedLimb is a limb of an non native integer
#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    // Witness value
    value: Option<Limb<F>>,
    // Cell that this value accomadates
    cell: Cell,
    // Maximum value to track overflow and reduction flow
    max_val: big_uint,
}

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: FieldExt> From<AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F>) -> Self {
        AssignedValue::new(limb.cell(), limb.value())
    }
}

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: FieldExt> From<&AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: &AssignedLimb<F>) -> Self {
        AssignedValue::new(limb.cell(), limb.value())
    }
}

impl<F: FieldExt> Assigned<F> for AssignedLimb<F> {
    fn value(&self) -> Option<F> {
        self.value.as_ref().map(|value| value.fe())
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> Assigned<F> for &AssignedLimb<F> {
    fn value(&self) -> Option<F> {
        self.value.as_ref().map(|value| value.fe())
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> AssignedLimb<F> {
    /// Given an assigned value and expected maximum value constructs new
    /// `AssignedLimb`
    fn from(assigned: AssignedValue<F>, max_val: big_uint) -> Self {
        let value = assigned.value().map(|value| Limb::<F>::new(value));
        let cell = assigned.cell();
        AssignedLimb {
            value,
            cell,
            max_val,
        }
    }

    /// Helper functions for maximum value tracking

    fn limb(&self) -> Option<Limb<F>> {
        self.value.clone()
    }

    fn max_val(&self) -> big_uint {
        self.max_val.clone()
    }

    fn add(&self, other: &Self) -> big_uint {
        self.max_val.clone() + other.max_val.clone()
    }

    fn add_add(&self, other_0: &Self, other_1: &Self) -> big_uint {
        self.max_val.clone() + other_0.max_val.clone() + other_1.max_val.clone()
    }

    fn mul2(&self) -> big_uint {
        self.max_val.clone() + self.max_val.clone()
    }

    fn mul3(&self) -> big_uint {
        self.max_val.clone() + self.max_val.clone() + self.max_val.clone()
    }

    fn add_big(&self, other: big_uint) -> big_uint {
        self.max_val.clone() + other
    }

    fn add_fe(&self, other: F) -> big_uint {
        self.add_big(fe_to_big(other))
    }
}

/// Witness integer that is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedInteger<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>);

impl<'a, W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    From<Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>
    for UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn from(integer: Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        UnassignedInteger(integer)
    }
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns indexed limb as ÏUnassignedValue`
    fn limb(&self, idx: usize) -> UnassignedValue<N> {
        self.0.as_ref().map(|e| e.limb(idx).fe()).into()
    }
}

///
#[derive(Debug, Clone)]
pub struct AssignedInteger<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    // Limbs of the emulated integer
    limbs: [AssignedLimb<N>; NUMBER_OF_LIMBS],
    /// Value in the scalar field
    native_value: AssignedValue<N>,
    /// Share rns across all `AssignedIntegers`s
    rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}

impl<'a, W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Creates a new [`AssignedInteger`].
    pub fn new(
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
        limbs: &[AssignedLimb<N>; NUMBER_OF_LIMBS],
        native_value: AssignedValue<N>,
    ) -> Self {
        AssignedInteger {
            limbs: limbs.clone(),
            native_value,
            rns,
        }
    }

    /// Returns assigned limbs
    pub fn limbs(&self) -> [AssignedLimb<N>; NUMBER_OF_LIMBS] {
        self.limbs.clone()
    }

    /// Returns value under native modulus
    pub fn native(&self) -> AssignedValue<N> {
        self.native_value
    }

    /// Witness form of the assigned integer that is used to derive further
    /// witnesses
    pub fn integer(&self) -> Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        let has_value = self.limbs[0].value.clone().map(|_| ());
        let limbs: Option<Vec<Limb<N>>> = has_value.map(|_| {
            let limbs = self.limbs.iter().map(|limb| limb.limb().unwrap()).collect();
            limbs
        });
        limbs.map(|limbs| Integer::new(limbs, Rc::clone(&self.rns)))
    }

    fn make_aux(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut max_shift = 0usize;
        let max_vals = self.max_vals();
        for (max_val, aux) in max_vals.iter().zip(self.rns.base_aux.iter()) {
            let mut shift = 1;
            let mut aux = aux.clone();
            while *max_val > aux {
                aux <<= 1usize;
                max_shift = std::cmp::max(shift, max_shift);
                shift += 1;
            }
        }

        Integer::from_limbs(
            &self
                .rns
                .base_aux
                .iter()
                .map(|aux_limb| big_to_fe(aux_limb << max_shift))
                .collect::<Vec<N>>()
                .try_into()
                .unwrap(),
            Rc::clone(&self.rns),
        )
    }

    fn max_val(&self) -> big_uint {
        compose(self.max_vals().to_vec(), BIT_LEN_LIMB)
    }

    fn max_vals(&self) -> [big_uint; NUMBER_OF_LIMBS] {
        self.limbs
            .iter()
            .map(|limb| limb.max_val())
            .collect::<Vec<big_uint>>()
            .try_into()
            .unwrap()
    }

    fn limb(&self, idx: usize) -> AssignedValue<N> {
        self.limbs[idx].clone().into()
    }
}
