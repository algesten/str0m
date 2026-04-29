use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .btree_map(["."])
        .compile_protos(&["proto/rtc_event_log2.proto"], &["proto/"])?;
    Ok(())
}
