use std::fs::read_dir;
use std::io;
use std::path::{Path, PathBuf};

#[allow(unused)]
struct FileLister;

#[allow(unused)]
pub fn list_files<R>(dir: &Path, map_fn: fn(PathBuf) -> R) -> io::Result<Vec<R>> {
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = Vec::new();

    if dir.is_dir() {
        stack.push(dir.to_path_buf());
    }

    while !stack.is_empty() {
        let c_dir = stack.pop().unwrap();

        for e in read_dir(c_dir.as_path())? {
            let e = e?.path();
            if e.is_file() {
                let mut d = c_dir.clone();
                d.push(e);

                files.push(map_fn(d));
            } else if e.is_dir() {
                let mut d = c_dir.clone();
                d.push(e);

                stack.push(d);
            }
        }
    }

    Ok(files)
}
