use plonky2_field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig, Hasher, GenericHashOut};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};

pub struct CropTransformation<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const L: usize,
> {
    x: u32, y: u32,
    w: u32, h: u32
}

impl<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const L: usize
> CropTransformation<F, C, D, L> {
    pub fn new(x: u32, y: u32, w: u32, h: u32) -> Self {
        Crop {
            x, y, w, h
        }
    }

    pub fn update_with_chunk_circuit(
        builder: &mut CircuitBuilder<F, D>,
        original_chunk: &[Target; L],
        edited_chunk: &[Target; L],
        chunk_number: usize,
    ) {
        

    }
}