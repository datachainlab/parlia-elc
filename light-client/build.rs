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
            blocks_per_epoch,
        )
        .unwrap();
    }

    {
        use std::io::Write;
        let mut file = std::fs::File::create("src/header/hardfork.rs").unwrap();
        let minimum_time_stamp_supported =
            std::env::var("MINIMUM_TIMESTAMP_SUPPORTED").unwrap_or_else(|_| "0".to_string());
        let minimum_height_supported =
            std::env::var("MINIMUM_HEIGHT_SUPPORTED").unwrap_or_else(|_| "0".to_string());
        writeln!(
            file,
            "pub const MINIMUM_TIMESTAMP_SUPPORTED: u64 = {};\npub const MINIMUM_HEIGHT_SUPPORTED: u64 = {};",
            minimum_time_stamp_supported,
            minimum_height_supported
        )
            .unwrap();
    }
}
