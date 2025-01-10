use std::env;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

fn main() {
    let include_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("include");
    let mut build = cxx_build::bridge("src/bridge.rs");
    let cpp_files = get_cpp_files();

    build
        .files(&cpp_files)
        .include(include_path)
        .flag("-std=c++20");

    build.compile("cppbwe");

    for file in cpp_files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    get_header_files().into_iter().for_each(|file| {
        println!("cargo:rerun-if-changed={}", file.display());
    });
    println!("cargo:rerun-if-changed=src/bridge.rs");
}

/// Returns a list of all C++ sources that should be compiled.
fn get_cpp_files() -> Vec<PathBuf> {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("src")
        .join("cpp");

    #[cfg_attr(target_os = "macos", expect(unused_mut, reason = "cfg"))]
    let mut files = get_files_from_dir(dir);

    files.retain(|e| e.to_str().unwrap().contains(".cc"));

    files
}

/// Returns a list of all header files that should be included.
fn get_header_files() -> Vec<PathBuf> {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("include");

    get_files_from_dir(dir)
}

/// Performs recursive directory traversal returning all the found files.
fn get_files_from_dir<P: AsRef<Path>>(dir: P) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(DirEntry::into_path)
        .collect()
}
