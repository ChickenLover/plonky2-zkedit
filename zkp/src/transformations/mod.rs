use plonky2::{
    hash::hash_types::RichField, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, goldilocks_field::GoldilocksField};

pub mod crop;
pub mod util;

pub trait Transformation {
    fn contribute_to_chunk_circuit(
        &self,
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        original_chunk: &[Target],
        edited_chunk: &[Target],
        chunk_number: usize,
        padding: Option<usize>,
    );
}
