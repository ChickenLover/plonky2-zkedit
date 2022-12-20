use plonky2::{
    hash::poseidon::PoseidonHash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::{GenericHashOut, Hasher},
};
use plonky2_field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

pub(crate) fn set_multiple_targets<F: Field>(
    inputs: &mut PartialWitness<F>,
    targets: &[Target],
    values: &[F],
) {
    for (target, value) in targets.iter().zip(values.iter()) {
        inputs.set_target(*target, *value);
    }
}

pub(crate) fn bytes_to_prime64<F: PrimeField64>(bytes: &[u8]) -> Vec<F> {
    let mut field_elements = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut elem_bytes = [0u8; 8];
        elem_bytes[..4].copy_from_slice(chunk);
        field_elements.push(F::from_canonical_u64(u64::from_be_bytes(elem_bytes)));
    }
    field_elements
}

pub fn calculate_poseidon(data: &[u8]) -> Vec<u8> {
    PoseidonHash::hash_pad(&bytes_to_prime64::<GoldilocksField>(data)).to_bytes()
}
