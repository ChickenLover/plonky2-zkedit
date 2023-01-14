use std::time::Instant;

use anyhow::Result;
use itertools::izip;
use log::Level;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_data::{CircuitData, VerifierCircuitTarget},
        proof::ProofWithPublicInputsTarget,
        prover::prove,
    },
    util::timing::TimingTree,
};

use crate::{
    hash::{ChunkHashTargets, ChunkHasher},
    proof::{ChunkProof, TransformationProof},
    util::bytes_to_field64,
    C, D, F,
};

pub(crate) struct TransformationChunkCircuit {
    pub(crate) circuit: CircuitData<F, C, D>,
    pub(crate) original_chunk: ChunkHashTargets,
    pub(crate) edited_chunk: ChunkHashTargets,
}

pub struct TransformationCircuit<const L: usize> {
    pub circuit: CircuitData<F, C, D>,
    pub(crate) chunk_circuits: Vec<TransformationChunkCircuit>,
    pub(crate) pts: Vec<ProofWithPublicInputsTarget<D>>,
    pub(crate) ids: Vec<VerifierCircuitTarget>,
}

impl<const L: usize> TransformationCircuit<L> {
    fn prove_chunk(
        &self,
        orig_hasher: &mut ChunkHasher<F, D, L>,
        edit_hasher: &mut ChunkHasher<F, D, L>,
        chunk_curcuit: &TransformationChunkCircuit,
    ) -> Result<ChunkProof> {
        let mut inputs = PartialWitness::<F>::new();
        orig_hasher.populate_chunk_inputs(&chunk_curcuit.original_chunk, &mut inputs);
        edit_hasher.populate_chunk_inputs(&chunk_curcuit.edited_chunk, &mut inputs);

        let mut timing = TimingTree::new("prove_chunk", Level::Info);
        let proof = prove(
            &chunk_curcuit.circuit.prover_only,
            &chunk_curcuit.circuit.common,
            inputs,
            &mut timing,
        )?;
        timing.print();

        chunk_curcuit.circuit.verify(proof.clone())?;

        Ok(ChunkProof { proof })
    }

    pub fn prove(&mut self, original: &[u8], edited: &[u8]) -> Result<TransformationProof> {
        let original_elements = bytes_to_field64::<F>(original);
        let edited_elements = bytes_to_field64::<F>(edited);

        println!(
            "Going to proof the hash of {} bytes. {} kB",
            original.len(),
            original.len() / 1024
        );
        let start = Instant::now();

        let mut orig_hasher = ChunkHasher::<F, D, L>::new(&original_elements);
        let mut edit_hasher = ChunkHasher::<F, D, L>::new(&edited_elements);

        let mut pw = PartialWitness::new();
        for (chunk_circuit, pt, inner_data) in izip!(&self.chunk_circuits, &self.pts, &self.ids) {
            println!("Proving chunk...");
            let chunk_proof =
                self.prove_chunk(&mut orig_hasher, &mut edit_hasher, chunk_circuit)?;
            pw.set_proof_with_pis_target(&pt, &chunk_proof.proof);
            pw.set_verifier_data_target(&inner_data, &chunk_circuit.circuit.verifier_only);
        }

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(
            &self.circuit.prover_only,
            &self.circuit.common,
            pw,
            &mut timing,
        )?;
        timing.print();

        let duration = start.elapsed();
        println!("Total time for prove is: {:?}", duration);

        Ok(TransformationProof {
            proof: proof.compress(
                &self.circuit.verifier_only.circuit_digest,
                &self.circuit.common,
            )?,
        })
    }
}
