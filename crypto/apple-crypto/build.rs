fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=swift");

    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }

    swift_rs::SwiftLinker::new("10.15")
        .with_ios("13.0")
        .with_package("Str0mCryptoKit", "swift")
        .link();
}
