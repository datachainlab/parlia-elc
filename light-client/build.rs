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
    {
        use std::io::Write;
        let mut file = std::fs::File::create("src/header/config.rs").unwrap();
        let luban_fork = std::env::var("BSC_LUBAN_FORK").unwrap_or_else(|_| "29020050".to_string());
        writeln!(file, "pub const LUBAN_FORK: u64 = {};", luban_fork).unwrap();
    }
}
