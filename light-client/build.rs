fn main() {
    use std::io::Write;
    let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
    let mut values: Vec<String> = vec![];
    #[cfg(feature = "dev")]
    {
        let blocks_per_epoch =
            std::env::var("BSC_BLOCKS_PER_EPOCH").unwrap_or_else(|_| "200".to_string());
        values.push(format!(
            "pub const BLOCKS_PER_EPOCH: u64 = {};",
            blocks_per_epoch
        ));
    }
    #[cfg(not(feature = "dev"))]
    {
        values.push(format!("pub const BLOCKS_PER_EPOCH: u64 = 200;"));
    }

    let minimum_time_stamp_supported =
        std::env::var("MINIMUM_TIMESTAMP_SUPPORTED").unwrap_or_else(|_| "0".to_string());
    values.push(format!(
        "pub const MINIMUM_TIMESTAMP_SUPPORTED: u64 = {};",
        minimum_time_stamp_supported
    ));
    let minimum_height_supported =
        std::env::var("MINIMUM_HEIGHT_SUPPORTED").unwrap_or_else(|_| "0".to_string());
    values.push(format!(
        "pub const MINIMUM_HEIGHT_SUPPORTED: u64 = {};",
        minimum_height_supported
    ));

    writeln!(file, "{}", values.join("\n").to_string()).unwrap();
}
