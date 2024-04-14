use sevenz_rust;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

fn bruteforce_decompress<R: Read + Seek>(
    src_reader: R,
    dest: impl AsRef<Path>,
    password_list: &[&str],
) -> Result<(), sevenz_rust::Error> {
    Ok(())
}

fn bruteforce_decompress_file(
    src_path: impl AsRef<Path>,
    dest: impl AsRef<Path>,
    password_list: &[&str],
) -> Result<(), sevenz_rust::Error> {
    let mut fd = File::open(src_path)?;

    loop {}

    Ok(())
}
