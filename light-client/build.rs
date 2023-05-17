fn main() {
    #[cfg(feature = "dev")]
    {
        use std::io::Write;
        if let Ok(block) = std::env::var("BLOCKS_PER_EPOCH") {
            let mut file = std::fs::File::create("src/header/constant.rs").unwrap();
            write!(file, "pub const BLOCKS_PER_EPOCH : u64 = {};", block).unwrap();
        }
    }
}
