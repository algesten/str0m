#!/usr/bin/env bash
set -euo pipefail

repo="$(git rev-parse --show-toplevel)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/str0m-ffi-isolation.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/copy" "$scratch/probe/src/bin"
git -C "$repo" archive HEAD | tar -xf - -C "$scratch/copy"
# Include tracked worktree changes so the fixture also tests fixes before commit.
git -C "$repo" diff --binary HEAD > "$scratch/worktree.patch"
if [[ -s "$scratch/worktree.patch" ]]; then
  git -C "$scratch/copy" apply --binary "$scratch/worktree.patch"
fi
cp "$repo/Cargo.lock" "$scratch/probe/Cargo.lock"

# Simulate a second independently sourced release with a different private ABI:
# its Swift bridge complements the digest and its Rust wrapper reverses that
# encoding. Both releases still implement the same public SHA-256 operation.
python3 - "$repo" "$scratch" <<'PY'
import json
import re
import sys
from pathlib import Path

repo, scratch = map(Path, sys.argv[1:])
copy = scratch / "copy"
for relative in ["crypto/apple-crypto/Cargo.toml", "crates/proto/Cargo.toml"]:
    path = copy / relative
    text = path.read_text()
    pattern = r'(?m)^version = "(\d+)\.(\d+)\.(\d+)"$'
    text, count = re.subn(
        pattern,
        lambda match: 'version = "{}.{}.{}"'.format(
            match[1], match[2], int(match[3]) + 1
        ),
        text,
        count=1,
    )
    assert count == 1
    path.write_text(text)

path = copy / "crypto/apple-crypto/swift/Sources/Str0mCryptoKit/CryptoKit.swift"
text = path.read_text()
old = '''        SHA256.hash(data: data).withUnsafeBytes {
            output.copyMemory(from: $0.baseAddress!, byteCount: 32)
        }
'''
new = old + '''        for index in 0..<32 {
            let byte = output.load(fromByteOffset: index, as: UInt8.self)
            output.storeBytes(of: byte ^ 0xff, toByteOffset: index, as: UInt8.self)
        }
'''
assert text.count(old) == 1
path.write_text(text.replace(old, new, 1))

path = copy / "crypto/apple-crypto/src/cryptokit.rs"
text = path.read_text()
old = '''pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    digest(data)
}'''
new = '''pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut digest: [u8; 32] = digest(data);
    for byte in &mut digest { *byte ^= 0xff; }
    digest
}'''
assert text.count(old) == 1
path.write_text(text.replace(old, new, 1))

probe = scratch / "probe"
original = json.dumps(str(repo / "crypto/apple-crypto"))
other = json.dumps(str(copy / "crypto/apple-crypto"))
(probe / "Cargo.toml").write_text(f'''[package]
name = "str0m-ffi-isolation-test"
version = "0.1.0"
edition = "2024"

[dependencies]
original = {{ package = "str0m-apple-crypto", path = {original} }}
other = {{ package = "str0m-apple-crypto", path = {other} }}
''')
check = '''let actual = PROVIDER::default_provider().sha256_provider.sha256(b"abc");
    assert_eq!(actual[0], 0xba);'''
for name, providers in [("original", ["original"]), ("other", ["other"]),
                        ("both", ["original", "other"])]:
    body = "\n    ".join(check.replace("PROVIDER", item) for item in providers)
    (probe / "src/bin" / (name + ".rs")).write_text("fn main() {\n    " + body + "\n}\n")
PY

export CARGO_TARGET_DIR="$scratch/target"
for binary in original other both; do
  cargo run --offline --manifest-path "$scratch/probe/Cargo.toml" --bin "$binary"
done
