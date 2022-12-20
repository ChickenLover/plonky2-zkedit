use std::slice::Chunks;

use anyhow::Result;
use plonky2::hash::hashing::{PlonkyPermutation, SPONGE_RATE, SPONGE_WIDTH};
use plonky2::iop::target::Target;
use plonky2_field::goldilocks_field::GoldilocksField;

use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{
    AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig,
};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

use crate::util::set_multiple_targets;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

/*
fn hashes_aggregate_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inners: &[ProofTuple<F, InnerC, D>],
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let mut last_result_state_target = builder.constants(&[F::ZERO; SPONGE_WIDTH]);

    for inner in inners {
        let (inner_proof, inner_vd, inner_cd) = inner;
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd);

        let init_state_target = &pt.public_inputs[..SPONGE_WIDTH];
        for (left, right) in last_result_state_target.iter().zip(init_state_target.iter()) {
            builder.connect(*left, *right);
        }
        last_result_state_target.copy_from_slice(&pt.public_inputs[SPONGE_WIDTH..]);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);

        pw.set_proof_with_pis_target(&pt, inner_proof);
        pw.set_verifier_data_target(&inner_data, inner_vd);
    }
    builder.register_public_inputs(&last_result_state_target[..4]);
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let proof = prove(&data.prover_only, &data.common, pw)?;
    println!("{:?}", proof.public_inputs);

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

fn general_recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inners: &[ProofTuple<F, InnerC, D>],
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    for inner in inners {
        let (inner_proof, inner_vd, inner_cd) = inner;
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);

        pw.set_proof_with_pis_target(&pt, inner_proof);
        pw.set_verifier_data_target(&inner_data, inner_vd);
    }
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
    println!("{:?}", proof.public_inputs);

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}
*/

/*
pub fn try_hashing (bytes: &[u8]) {
    let config = CircuitConfig::standard_recursion_config();
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Recursively verify the proof
    let middle = hashes_aggregate_proof::<F, C, C, D>(&inners, &config, None).unwrap();
    let (middle_proof, _, cd) = &middle;
    info!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );

    assert_eq!(middle_proof.public_inputs, true_hash);

    // Add a second layer of recursion to shrink the proof size further
    let outer = general_recursive_proof::<F, C, C, D>(&[middle], &config, None).unwrap();
    let (proof, vd, cd) = &outer;
    info!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );

}
*/

pub struct ChunkHasher<F: RichField + Extendable<D>, const D: usize, const L: usize> {
    data: Vec<F>,
    true_hash: [F; 4],
    states: Vec<[F; SPONGE_WIDTH]>,
    current_chunk: usize,
    total_chunks: usize,
}

impl<'a, F: RichField + Extendable<D>, const D: usize, const L: usize> ChunkHasher<F, D, L> {
    pub fn new(data: &[F]) -> Self {
        let true_hash = PoseidonHash::hash_pad(&data).elements;
        println!("True hash in goldilocks is {:?}", true_hash);

        let mut states = Vec::new();
        let initial_state = [F::ZERO; SPONGE_WIDTH];
        states.push(initial_state);

        Self {
            data: data.to_vec(),
            true_hash: true_hash,
            states: states,
            current_chunk: 0,
            total_chunks: (data.len() + L - 1) / L,
        }
    }

    pub fn total_chunks(&self) -> usize {
        self.total_chunks
    }

    fn pad_chunk(chunk: &mut Vec<F>) {
        chunk.push(F::ONE);
        while (chunk.len() + 1) % SPONGE_WIDTH != 0 {
            chunk.push(F::ZERO);
        }
        chunk.push(F::ONE);
    }

    pub fn will_pad(&self) -> Option<usize> {
        if self.current_chunk == self.total_chunks - 1 {
            Some(self.get_current_chunk().len())
        } else {
            None
        }
    }

    // TO-DO: clean
    fn get_current_chunk(&self) -> &[F] {
        &self.data
            [L * self.current_chunk..std::cmp::min(self.data.len(), L * (self.current_chunk + 1))]
    }

    fn prepare_chunk_prove_data(&self) -> ([F; SPONGE_WIDTH], Vec<F>, [F; SPONGE_WIDTH]) {
        let initial_state = *self.states.last().unwrap();
        let mut state = initial_state.clone();

        let mut chunk = self.get_current_chunk().to_vec();

        // Apply padding for the last chunk
        if self.current_chunk == self.total_chunks - 1 {
            Self::pad_chunk(&mut chunk);
        }

        // Calculate next state
        for input_chunk in chunk.chunks(SPONGE_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = PoseidonPermutation::permute(state);
        }

        (initial_state, chunk, state)
    }

    pub fn generate_next_chunk_contribution(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        inputs: &mut PartialWitness<F>,
    ) -> Vec<Target> {
        let (initial_state, chunk, result_state) = self.prepare_chunk_prove_data();
        self.current_chunk += 1;
        self.states.push(result_state);

        let hash_input_targets = builder.add_virtual_targets(chunk.len());
        let init_state_targets = builder.add_virtual_target_arr::<SPONGE_WIDTH>();
        let result_state_targets =
            builder.permute_many::<PoseidonHash>(init_state_targets, hash_input_targets.clone());

        builder.register_public_inputs(&init_state_targets);
        builder.register_public_inputs(&result_state_targets);
        builder.print_gate_counts(0);

        set_multiple_targets(inputs, &init_state_targets, &initial_state);
        set_multiple_targets(inputs, &hash_input_targets, &chunk);
        set_multiple_targets(inputs, &result_state_targets, &result_state);

        hash_input_targets
    }
}
