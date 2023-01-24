use serde::{Deserialize, Serialize};
use zkedit_transformations::Transformation;
use zkedit_zkp::proof::TransformationProof;

#[derive(Serialize, Deserialize)]
pub struct ProofMetadata {
    pub(crate) proof: TransformationProof,
    pub(crate) original_length: usize,
    pub(crate) edited_length: usize,
    pub(crate) transformation: Transformation,
}
