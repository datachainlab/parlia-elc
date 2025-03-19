fn main() {
    use std::io::Write;
    let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
    let mut values: Vec<String> = vec![];
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

    writeln!(file, "{}", values.join("\n")).unwrap();
}
