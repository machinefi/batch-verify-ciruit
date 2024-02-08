use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Column, Error, Fixed, Selector},
    halo2curves::ff::PrimeField,
};

pub mod utils;
pub use halo2_proofs;
pub use halo2_curves as curves;

// use super::FieldExt;

pub struct RegionCtx<'a, 'b, F: Field> {
    pub region: &'a mut Region<'b, F>,
    pub offset: &'a mut usize,
}

impl<'a, 'b, F: PrimeField> RegionCtx<'a, 'b, F> {
    pub fn new(region: &'a mut Region<'b, F>, offset: &'a mut usize) -> RegionCtx<'a, 'b, F> {
        RegionCtx { region, offset }
    }

    pub fn assign_fixed(
        &mut self,
        annotation: &str,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.region
            .assign_fixed(|| annotation, column, *self.offset, || Value::known(value))
    }

    pub fn assign_advice(
        &mut self,
        annotation: &str,
        column: Column<Advice>,
        value: Option<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let v = value.ok_or(Error::Synthesis)?;
        self.region.assign_advice(
            || annotation,
            column,
            *self.offset,
            || Value::known(v)
        )
    }

    pub fn constrain_equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(self.region, *self.offset)
    }

    pub fn next(&mut self) {
        *self.offset += 1
    }
}
