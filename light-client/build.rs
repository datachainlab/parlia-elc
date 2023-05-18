fn main() {
    #[cfg(feature = "dev")]
    {
        use std::io::Write;
        let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
        let blocks_per_epoch = std::env::var("BLOCKS_PER_EPOCH").unwrap_or("200".to_string());
        let luban_fork = std::env::var("LUBAN_FORM").unwrap_or("29295050".to_string());
        write!(
            file,
            "pub const BLOCKS_PER_EPOCH: u64 = {};\n",
            blocks_per_epoch
        )
        .unwrap();
        write!(file, "pub const LUBAN_FORK: u64 = {};", luban_fork).unwrap();
    }
}
