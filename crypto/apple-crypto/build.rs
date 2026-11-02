use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=swift");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple") {
        return;
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("unsupported Apple target architecture: {other:?}"),
    };
    let target = env::var("TARGET").expect("TARGET not set");
    let (sdk, swift_target) = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => ("macosx", format!("{arch}-apple-macosx10.15")),
        Ok("ios") if target.ends_with("-macabi") => {
            panic!("Mac Catalyst is not supported by the Swift runtime linker")
        }
        Ok("ios") if target.ends_with("-sim") || arch == "x86_64" => {
            // Apple Silicon simulators first appeared in iOS 14.
            let minimum = if arch == "arm64" { "14.0" } else { "13.0" };
            (
                "iphonesimulator",
                format!("{arch}-apple-ios{minimum}-simulator"),
            )
        }
        Ok("ios") => ("iphoneos", format!("{arch}-apple-ios13.0")),
        other => panic!("unsupported Apple target operating system: {other:?}"),
    };

    let sdk_path = Command::new("xcrun")
        .args(["--sdk", sdk, "--show-sdk-path"])
        .output()
        .expect("failed to run xcrun");
    assert!(
        sdk_path.status.success(),
        "failed to find {sdk} SDK: {}",
        String::from_utf8_lossy(&sdk_path.stderr)
    );
    let sdk_path = String::from_utf8(sdk_path.stdout).expect("SDK path is not UTF-8");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let mut sources: Vec<_> = fs::read_dir("swift/Sources/Str0mCryptoKit")
        .expect("failed to read Swift bridge sources")
        .map(|entry| entry.expect("failed to read Swift bridge source").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "swift"))
        .collect();
    sources.sort();
    assert!(!sources.is_empty(), "no Swift bridge sources found");

    // swift-rs supplies the Swift runtime link paths. Compile our dependency-free
    // bridge directly so SwiftPM cannot substitute the host architecture, raise
    // the deployment target, or place the archive in an unexpected directory.
    let mut swiftc = Command::new("swiftc");
    swiftc
        .args(["-emit-library", "-static", "-module-name", "Str0mCryptoKit"])
        .args(["-target", &swift_target, "-sdk", sdk_path.trim()])
        .arg("-o")
        .arg(out_dir.join("libStr0mCryptoKit.a"))
        .args(sources);
    if env::var("OPT_LEVEL").as_deref() != Ok("0") {
        swiftc.arg("-O");
    }
    assert!(
        swiftc.status().expect("failed to run swiftc").success(),
        "failed to compile the Swift CryptoKit bridge"
    );

    swift_rs::SwiftLinker::new("10.15").with_ios("13.0").link();
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=Str0mCryptoKit");
}
