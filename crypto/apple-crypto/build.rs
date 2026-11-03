use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

fn hash_part(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn deployment_target(variable: &str, minimum: &str) -> String {
    let target = env::var(variable).unwrap_or_else(|_| minimum.to_owned());
    let version = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .map(|part| {
                part.parse()
                    .unwrap_or_else(|_| panic!("invalid {variable}: {target}"))
            })
            .collect()
    };
    if version(&target) < version(minimum) {
        minimum.to_owned()
    } else {
        target
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=swift");
    println!("cargo:rerun-if-changed=src/cryptokit.rs");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=IPHONEOS_DEPLOYMENT_TARGET");

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
        Ok("macos") => {
            let minimum = deployment_target("MACOSX_DEPLOYMENT_TARGET", "10.15");
            ("macosx", format!("{arch}-apple-macosx{minimum}"))
        }
        Ok("ios") if target.ends_with("-macabi") => {
            panic!("Mac Catalyst is not supported by the Swift runtime linker")
        }
        Ok("ios") if target.ends_with("-sim") || arch == "x86_64" => {
            // Apple Silicon simulators first appeared in iOS 14.
            let minimum = if arch == "arm64" { "14.0" } else { "13.0" };
            let minimum = deployment_target("IPHONEOS_DEPLOYMENT_TARGET", minimum);
            (
                "iphonesimulator",
                format!("{arch}-apple-ios{minimum}-simulator"),
            )
        }
        Ok("ios") => {
            let minimum = deployment_target("IPHONEOS_DEPLOYMENT_TARGET", "13.0");
            ("iphoneos", format!("{arch}-apple-ios{minimum}"))
        }
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

    // Different crate versions or source revisions can coexist in one process.
    // Namespace both the C exports and Swift module by the private bridge code
    // so a Rust wrapper cannot accidentally call another copy's implementation.
    let mut digest = Sha256::new();
    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");
    hash_part(&mut digest, version.as_bytes());
    let build_script = fs::read("build.rs").expect("failed to read build script");
    hash_part(&mut digest, &build_script);
    let rust_bridge = fs::read("src/cryptokit.rs").expect("failed to read Rust bridge source");
    hash_part(&mut digest, &rust_bridge);
    let swift_sources: Vec<_> = sources
        .iter()
        .map(|path| {
            let source = fs::read_to_string(path).expect("failed to read Swift bridge source");
            hash_part(&mut digest, path.to_string_lossy().as_bytes());
            hash_part(&mut digest, source.as_bytes());
            (path, source)
        })
        .collect();
    let fingerprint: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let module_name = format!("Str0mCryptoKit_{fingerprint}");
    let symbol_prefix = format!("str0m_cryptokit_{fingerprint}_");
    let generated_dir = out_dir.join("swift-sources");
    fs::create_dir_all(&generated_dir).expect("failed to create Swift source directory");
    let generated_sources: Vec<_> = swift_sources
        .iter()
        .map(|(path, source)| {
            let generated = generated_dir.join(path.file_name().expect("Swift source has no name"));
            fs::write(
                &generated,
                source.replace("str0m_cryptokit_", &symbol_prefix),
            )
            .expect("failed to write namespaced Swift source");
            generated
        })
        .collect();
    println!("cargo:rustc-env=STR0M_CRYPTOKIT_PREFIX={symbol_prefix}");

    // swift-rs supplies the Swift runtime link paths. Compile our dependency-free
    // bridge directly so SwiftPM cannot substitute the host architecture, raise
    // the deployment target, or place the archive in an unexpected directory.
    let mut swiftc = Command::new("swiftc");
    swiftc
        .args(["-emit-library", "-static", "-module-name", &module_name])
        .args(["-target", &swift_target, "-sdk", sdk_path.trim()])
        .arg("-o")
        .arg(out_dir.join(format!("lib{module_name}.a")))
        .args(generated_sources);
    if env::var("OPT_LEVEL").as_deref() != Ok("0") {
        swiftc.arg("-O");
    }
    assert!(
        swiftc.status().expect("failed to run swiftc").success(),
        "failed to compile the Swift CryptoKit bridge"
    );

    swift_rs::SwiftLinker::new("10.15").with_ios("13.0").link();
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={module_name}");
}
