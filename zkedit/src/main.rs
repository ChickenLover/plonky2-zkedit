use anyhow::Result;
use image::imageops::crop;
use image::ImageBuffer;
use log::{info, Level, LevelFilter};
use structopt::StructOpt;

use image::io::Reader as ImageReader;
use image::{buffer::Pixels, Rgba};

use zkedit_zkp::transformations::crop::CropTransformation;
use zkedit_zkp::util::calculate_poseidon;
use zkedit_zkp::TransformationProver;

#[derive(Clone, StructOpt, Debug)]
#[structopt(name = "zkedit_options")]
struct Options {
    /// A path to original img file
    orig_img_path: String,

    /// X coordinate of crop upper left pixel
    #[structopt(short = "x", default_value = "55")]
    crop_x: u32,

    /// Y coordinate of crop upper left pixel
    #[structopt(short = "y", default_value = "30")]
    crop_y: u32,

    /// Width of the crop
    #[structopt(short = "w", default_value = "446")]
    crop_w: u32,

    /// Height of the crop
    #[structopt(short = "h", default_value = "361")]
    crop_h: u32,
}

fn pixels_to_bytes(pixels: Pixels<Rgba<u8>>) -> Vec<u8> {
    let mut pixel_bytes = vec![];
    for pixel in pixels {
        pixel_bytes.extend_from_slice(&pixel.0)
    }
    pixel_bytes
}

fn align_crop_edit(
    crop_img: ImageBuffer<Rgba<u8>, Vec<u8>>,
    orig_width: u32,
    orig_height: u32,
    crop_x: u32,
    crop_y: u32,
    crop_width: u32,
    crop_height: u32,
) -> Vec<u8> {
    let lx_bound = crop_x;
    let rx_bound = crop_x + crop_width;
    let uy_bound = crop_y;
    let dy_bound = crop_y + crop_height;

    let mut aligned_image = ImageBuffer::new(orig_width, orig_height);
    for (x, y, pixel) in aligned_image.enumerate_pixels_mut() {
        if x >= lx_bound && x < rx_bound && y >= uy_bound && y < dy_bound {
            *pixel = crop_img.get_pixel(x - crop_x, y - crop_y).clone();
        }
    }

    pixels_to_bytes(aligned_image.pixels())
}

const L: usize = 12 * 85 * 256;

fn main() -> Result<()> {
    let options = Options::from_args_safe()?;

    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    //builder.filter_level(LevelFilter::Debug);
    //builder.filter_level(LevelFilter::Trace);
    builder.try_init();

    let mut img = ImageReader::open(options.orig_img_path)?
        .decode()?
        .into_rgba8();
    let pixels = img.pixels();
    let width = img.width();
    let height = img.height();
    let bytes_length = width * height * 4;

    println!(
        "Read image {}x{} pixels. {}B, {}kB, {}mB",
        width,
        height,
        bytes_length,
        bytes_length / 1024,
        bytes_length / (1024 * 1024)
    );

    let pixel_bytes = pixels_to_bytes(pixels);
    let pixels_hash = calculate_poseidon(&pixel_bytes);

    println!("Pixels hash: {:?}", pixels_hash);

    let crop_img = crop(
        &mut img,
        options.crop_x,
        options.crop_y,
        options.crop_w,
        options.crop_h,
    )
    .to_image();

    println!(
        "Crop image {}x{} pixels",
        crop_img.width(),
        crop_img.height()
    );

    let mut crop_bytes = pixels_to_bytes(crop_img.pixels());
    crop_bytes.extend(std::iter::repeat(0).take(pixel_bytes.len() - crop_bytes.len()));

    crop_img.save("img_crop.png");

    let alidned_crop_bytes = align_crop_edit(
        crop_img,
        width,
        height,
        options.crop_x,
        options.crop_y,
        options.crop_w,
        options.crop_h,
    );

    let crop_transform = CropTransformation::<L>::new(
        width,
        height,
        options.crop_x,
        options.crop_y,
        options.crop_w,
        options.crop_h,
    );
    let mut prover =
        TransformationProver::<L>::new(&pixel_bytes, &alidned_crop_bytes, Box::new(crop_transform));

    prover.prove().expect("Error while trying to prove...");

    Ok(())
}
