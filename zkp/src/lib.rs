pub mod hash;
pub mod transformations;
pub mod util;

use anyhow::Result;
use hash::ChunkHasher;
use log::Level;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        prover::prove,
    },
    util::timing::TimingTree,
};
use plonky2_field::{extension::Extendable, goldilocks_field::GoldilocksField};
use std::time::Instant;
use transformations::Transformation;

use crate::util::bytes_to_prime64;

pub struct TransformationProver<const L: usize> {
    original: Vec<GoldilocksField>,
    edited: Vec<GoldilocksField>,
    transformation: Box<dyn Transformation>,
    orig_hasher: ChunkHasher<GoldilocksField, 2, L>,
    edit_hasher: ChunkHasher<GoldilocksField, 2, L>,
}

impl<const L: usize> TransformationProver<L> {
    pub fn new(original: &[u8], edited: &[u8], transformation: Box<dyn Transformation>) -> Self {
        assert_eq!(original.len(), edited.len());
        let original_elements = bytes_to_prime64::<GoldilocksField>(original);
        let edited_elements = bytes_to_prime64::<GoldilocksField>(edited);

        let orig_hasher = ChunkHasher::<GoldilocksField, 2, L>::new(&original_elements);
        let edit_hasher = ChunkHasher::<GoldilocksField, 2, L>::new(&edited_elements);

        Self {
            original: original_elements.to_vec(),
            edited: edited_elements.to_vec(),
            transformation,
            orig_hasher,
            edit_hasher,
        }
    }

    pub fn prove(&mut self) -> Result<()> {
        println!(
            "Going to proof the hash of {} bytes. {} kB",
            self.original.len() * 4,
            self.original.len() * 4 / 1024
        );
        let start = Instant::now();

        // let mut inners = Vec::new();

        let config = CircuitConfig::standard_recursion_config();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        for chunk in 0..self.orig_hasher.total_chunks() {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            let mut inputs = PartialWitness::<GoldilocksField>::new();

            let will_pad = self.orig_hasher.will_pad();

            let orig_targets = self
                .orig_hasher
                .generate_next_chunk_contribution(&mut builder, &mut inputs);
            let edit_targets = self
                .edit_hasher
                .generate_next_chunk_contribution(&mut builder, &mut inputs);

            self.transformation.contribute_to_chunk_circuit(
                &mut builder,
                &orig_targets,
                &edit_targets,
                chunk,
                will_pad               
            );
            let circuit = builder.build::<C>();
            let mut timing = TimingTree::new("prove", Level::Debug);
            let proof = prove(&circuit.prover_only, &circuit.common, inputs, &mut timing)?;
            timing.print();
            println!("{:?}", proof.public_inputs);

            circuit.verify(proof.clone())?;
        }

        let duration = start.elapsed();
        println!("Total time for prove is: {:?}", duration);
        /*
        let (_, _, cd) = &inner;
        // Start with a dummy proof of specified size
        info!(
            "Initial proof degree {} = 2^{}",
            cd.degree(),
            cd.degree_bits()
        );
        inners.push(inner);
        states.push(state);
        */

        Ok(())
    }
}
