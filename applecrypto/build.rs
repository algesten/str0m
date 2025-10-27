fn main() {
    println!("cargo:rustc-link-lib=framework=Network");
    // On macOS, libdispatch (Grand Central Dispatch) is typically available as part of libSystem,
    // but we need to explicitly link it for the dispatch_get_main_queue function
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-search=native=/usr/lib");
}
