#![feature(thread_spawn_unchecked)]

extern crate num_cpus;

mod mobi;
mod lz77;

use std::fs;
use std::error::Error;
use std::env;
use std::process;
use crate::mobi::{ MobiReader, Mobi };

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Required arguments: <input_file_path> <output_file_path>");
        process::exit(1);
    }
    let input_path = &args[1];
    let output_path = &args[2];
    let reader = MobiReader::new(input_path)?;
    let mobi = MobiReader::read(&reader);
    Mobi::display_summary(&mobi);
    let text = Mobi::dump_text(&mobi)?;
    let text = text.as_str();
    fs::write(output_path, text)?;

    // Just testing that our compression stuff works
    test_compress_decompress(text);

    Ok(())
}

fn test_compress_decompress(text: &str) {
    let start = std::time::Instant::now();
    let compressed_blocks = lz77::compress_all(text.as_bytes());
    let end = std::time::Instant::now();
    println!("Compressed in {} ms.", end.duration_since(start).as_millis());
    
    let decompressed = lz77::decompress_all(&compressed_blocks);
    assert_eq!(text, std::str::from_utf8(&decompressed).unwrap());
}
