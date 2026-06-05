# Release

How to release str0m and its workspace crates.

## Crate dependency graph

```
                              str0m
                                |
       +------+-----------+-----+-----+------------+----------+
       |      |           |           |            |          |
       v      v           v           v            v          v
      is   aws-lc-rs  rust-crypto  openssl   apple-crypto  wincrypto
       |      |           |           |            |          |
       +------+-----------+-----+-----+------------+----------+
                                |
                                v
                           str0m-proto
```

`str0m-netem` is dev-only — not pulled by published str0m.

## Bumping rules

- **str0m-proto**: bump minor (0.x.0) when `dimpl` workspace dep crosses a 0.x boundary, since `proto` re-exports dimpl types (`DtlsCert`, `KeyingMaterial`, `SrtpProfile`, etc.). Patch is fine for internal-only changes.
- **Crypto crates** (`str0m-aws-lc-rs`, `str0m-rust-crypto`, `str0m-openssl`, `str0m-apple-crypto`, `str0m-wincrypto`): bump minor when `dimpl` crosses a 0.x boundary or when their dep on `str0m-proto` crosses a 0.x boundary.
- **is**: bump minor when its dep on `str0m-proto` crosses a 0.x boundary. Patch for additive API or bug fixes that don't touch the public proto-derived surface.
- **str0m**: minor bump per release that includes any breaking change or new public API.

## The trap: don't publish leaf crates ahead of a shared-dep bump

If a release will bump `str0m-proto` (or `dimpl` such that proto must bump), **do not** publish `is` or any crypto crate against the old proto first. They'll get pinned to the old `^0.x` proto on the registry, and the next time you publish str0m it will pull two proto versions into the dep tree — types like `TcpType` won't unify and verification fails:

```
expected `str0m_proto::net::TcpType`, found `TcpType`
```

The only fix is another minor bump of the prematurely-published crate. We hit this in 0.19.0 — `is` had to go 0.8.0 → 0.8.1 → 0.9.0 in one release cycle.

**Rule:** decide up front whether `str0m-proto` is bumping in this release. If yes, bump it (and everything that depends on it) in a single batch.

## Release procedure

1. Decide bumps for each crate (see rules above). Update versions in:
   - `Cargo.toml` (root `[package]` and `[workspace.dependencies]`)
   - Each sub-crate's `Cargo.toml`
2. Move `# Unreleased` in `CHANGELOG.md` to `# <new-version>`.
3. `cargo check --workspace` to refresh `Cargo.lock` and confirm it builds.
4. Commit with message `<version>` (e.g. `0.19.0`), tag, push:
   ```
   git tag 0.19.0
   git push && git push --tags
   ```
5. Publish bottom-up. Each step waits for the previous to land on the index:
   ```
   cargo publish -p str0m-proto
   cargo publish -p is
   cargo publish -p str0m-aws-lc-rs
   cargo publish -p str0m-rust-crypto
   cargo publish -p str0m-openssl
   cargo publish -p str0m-apple-crypto
   cargo publish -p str0m-wincrypto --no-verify
   cargo publish -p str0m
   ```
6. Skip any line whose version is already on crates.io (e.g. mid-release recovery).

## Notes on individual crates

- **`str0m-wincrypto`** — verify step pulls the `windows` crate, which fails to build on macOS due to upstream issues. Use `--no-verify`. CI on Windows is the real verification.
- **`str0m-netem`** — dev-only. Bump and republish only if its source changes; not required for a str0m release.
- **`is`** — independent tags are allowed (`is-0.x.y`), but read "the trap" above before publishing one out of band.

## Verifying state on crates.io

```
for c in str0m str0m-proto is str0m-aws-lc-rs str0m-rust-crypto \
         str0m-openssl str0m-apple-crypto str0m-wincrypto; do
  echo -n "$c: "
  curl -s "https://crates.io/api/v1/crates/$c" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])"
done
```
