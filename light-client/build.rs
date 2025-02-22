fn main() {
    #[cfg(feature = "dev")]
    {
        use std::io::Write;
        let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
        let blocks_per_epoch =
            std::env::var("BSC_BLOCKS_PER_EPOCH").unwrap_or_else(|_| "1000".to_string());
        let blocks_per_epoch_before_rolentz = std::env::var("BSC_BLOCKS_PER_EPOCH_BEFORE_ROLENTZ")
            .unwrap_or_else(|_| "200".to_string());
        writeln!(
            file,
            "pub const BLOCKS_PER_EPOCH: u64 = {};\npub const BLOCKS_PER_EPOCH_BEFORE_ROLENTZ: u64 = {};",
            blocks_per_epoch,
            blocks_per_epoch_before_rolentz
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
        let pascal_timestamp =
            std::env::var("PASCAL_TIMESTAMP").unwrap_or_else(|_| "0".to_string());
        let rolentz_height =
            std::env::var("ROLENTZ_HEIGHT").unwrap_or_else(|_| "10000000000".to_string());
        writeln!(
            file,
            "pub const MINIMUM_TIMESTAMP_SUPPORTED: u64 = {};\npub const MINIMUM_HEIGHT_SUPPORTED: u64 = {};\npub const PASCAL_TIMESTAMP: u64 = {};\npub const ROLENTZ_HEIGHT: u64 = {};",
            minimum_time_stamp_supported,
            minimum_height_supported,
            pascal_timestamp,
            rolentz_height
        )
            .unwrap();
    }
}
