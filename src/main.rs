#![feature(thread_spawn_unchecked)]

extern crate num_cpus;

mod mobi;
mod lz77;

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
    Mobi::dump_text_to_file_concurrent(&mobi, output_path, num_cpus::get())?;
    Ok(())
}