fn main() {
    #[cfg(feature = "dev")]
    {
        use std::io::Write;
        let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
        let blocks_per_epoch =
            std::env::var("BSC_BLOCKS_PER_EPOCH").unwrap_or_else(|_| "200".to_string());
        writeln!(
            file,
            "pub const BLOCKS_PER_EPOCH: u64 = {};",
            blocks_per_epoch
        )
        .unwrap();
    }
}
