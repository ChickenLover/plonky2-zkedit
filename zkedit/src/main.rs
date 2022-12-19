use std::fs;

use zkedit_zkp::hash::{calculate_poseidon, try_hashing};
use image::imageops::crop;
use structopt::StructOpt;
use anyhow::Result;

use image::{buffer::Pixels, Rgba};
use image::io::Reader as ImageReader;

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

fn main() -> Result<()> {
    let options = Options::from_args_safe()?;
    let mut img = ImageReader::open(options.orig_img_path)?.decode()?.into_rgba8();
    let pixels = img.pixels();
    let width = img.width();
    let height = img.height();
    let bytes_length = width * height * 4;

    println!("Read image {}x{} pixels. {}B, {}kB, {}mB",
            width, height, bytes_length,
            bytes_length / 1024, bytes_length / (1024 * 1024));

    let pixel_bytes = pixels_to_bytes(pixels);
    let pixels_hash = calculate_poseidon(&pixel_bytes);

    println!("Pixels hash: {:?}", pixels_hash);

    let crop_img = crop(
        &mut img,
        options.crop_x, options.crop_y,
        options.crop_w, options.crop_h
    ).to_image();

    println!("Crop image {}x{} pixels", crop_img.width(), crop_img.height());

    crop_img.save("img_crop.png");

    try_hashing(&pixel_bytes);
    try_hashing(&pixels_to_bytes(crop_img.pixels()));
    Ok(())
}