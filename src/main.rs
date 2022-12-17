use anyhow::Result;
use log::{info, Level, LevelFilter};
use plonky2::hash::hashing::{SPONGE_WIDTH, PlonkyPermutation, SPONGE_RATE};
use std::time::Instant;

use plonky2_field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn hash_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    init_state: [F; SPONGE_WIDTH],
    result_state: [F; SPONGE_WIDTH],
    elements: &[F]
) -> Result<ProofTuple<F, C, D>> {
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    //let mut field_elements = field_bytes.clone();
    //fake_bytes[0] += F::ONE;
    //let fake_hash_result = PoseidonHash::hash_no_pad(&fake_bytes); // hash_x = hash(x)
    
    println!("Init state: {:?}", init_state);
    println!("Result state: {:?}", result_state);

    let hash_input_targets = builder.add_virtual_targets(elements.len());
    let init_state_target = builder.add_virtual_target_arr::<SPONGE_WIDTH>();
    let result_state_target = builder.permute_many::<PoseidonHash>(init_state_target, hash_input_targets.clone());

    builder.register_public_inputs(&init_state_target);
    builder.register_public_inputs(&result_state_target);
    builder.print_gate_counts(0);

    let data = builder.build::<C>();
    let mut inputs = PartialWitness::new();
    for (target, value) in init_state_target.iter().zip(init_state.iter()) {
        inputs.set_target(*target, *value);
    }

    for (target, value) in hash_input_targets.iter().zip(elements.iter()) {
        inputs.set_target(*target, *value);
    }

    for (target, value) in result_state_target.iter().zip(result_state.iter()) {
        inputs.set_target(*target, *value);
    }

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
    timing.print();
    println!("{:?}", proof.public_inputs);
    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

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

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
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

const HASH_INPUT_SIZE: usize = 1024 * 1024 * 4;

fn main() {
    let config = CircuitConfig::standard_recursion_config();
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    //builder.filter_level(LevelFilter::Debug);
    //builder.filter_level(LevelFilter::Trace);
    builder.try_init().unwrap();


    let start = Instant::now();

    let mut inners = Vec::new();

    let blocks = 4;
    let bytes = vec![1u8; HASH_INPUT_SIZE * blocks];

    let mut field_elements = Vec::<F>::new();
    for chunk in bytes.chunks(8) {
        let mut elem_bytes = [0u8; 8];
        elem_bytes.copy_from_slice(chunk);
        field_elements.push(F::from_canonical_u64(u64::from_be_bytes(elem_bytes)));
    }
    println!("Going to proof the hash of {} bytes. {} kB", blocks * HASH_INPUT_SIZE, blocks * HASH_INPUT_SIZE / 1024);

    let true_hash = PoseidonHash::hash_no_pad(&field_elements).elements;
    println!("True hash is {:?}", true_hash);

    let mut states = Vec::new();
    let mut state = [F::ZERO; SPONGE_WIDTH];
    states.push(state);
    for bytes_chunk in field_elements.chunks(HASH_INPUT_SIZE >> 3) {
        for input_chunk in bytes_chunk.chunks(SPONGE_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = PoseidonPermutation::permute(state);
        }

        let mut init_state = [F::ZERO; SPONGE_WIDTH];
        init_state.copy_from_slice(states.last().unwrap());
        let inner = hash_proof::<F, C, D>(
            &config,
            init_state,
            state.clone(),
            &bytes_chunk
        ).unwrap();

        let (_, _, cd) = &inner;
        // Start with a dummy proof of specified size
        info!(
            "Initial proof degree {} = 2^{}",
            cd.degree(),
            cd.degree_bits()
        );
        inners.push(inner);
        states.push(state);
    }

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

    let duration = start.elapsed();
    println!("Total time is: {:?}", duration);
}
