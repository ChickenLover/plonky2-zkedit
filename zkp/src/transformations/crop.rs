use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;

use super::util::pixel_number_to_coords;
use super::Transformation;

pub struct CropTransformation<const L: usize> {
    orig_w: u32,
    orig_h: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

impl<const L: usize> CropTransformation<L> {
    pub fn new(orig_w: u32, orig_h: u32, x: u32, y: u32, w: u32, h: u32) -> Self {
        Self {
            orig_w,
            orig_h,
            x,
            y,
            w,
            h,
        }
    }
}

impl<const L: usize> Transformation for CropTransformation<L> {
    fn contribute_to_chunk_circuit(
        &self,
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        original_chunk: &[Target],
        edited_chunk: &[Target],
        chunk_number: usize,
        padding: Option<usize>,
    ) {
        let lx_bound = self.x;
        let rx_bound = self.x + self.w;
        let uy_bound = self.y;
        let dy_bound = self.y + self.h;
        for (i, (orig_pixel, edit_pixel)) in original_chunk.iter().zip(edited_chunk).enumerate() {
            // Don't prove anything for padding
            if let Some(pad_index) = padding {
                if i >= pad_index {
                    continue;
                }
            }

            let (x, y) = pixel_number_to_coords(chunk_number * L + i, self.orig_w);
            if x >= lx_bound && x < rx_bound && y >= uy_bound && y < dy_bound {
                builder.is_equal(*orig_pixel, *edit_pixel);
            } else {
                builder.assert_zero(*edit_pixel);
            }
        }
    }
}
