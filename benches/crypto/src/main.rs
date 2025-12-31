// This crate is only for benchmarks
fn main() {
    println!("Run `cargo bench` to execute the crypto comparison benchmarks.");
    println!();
    println!("For native CPU optimizations:");
    println!("  RUSTFLAGS=\"-C target-cpu=native\" cargo bench");
}
