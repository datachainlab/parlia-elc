use hex_literal::hex;
use prost::bytes::BytesMut;
use rlp::RlpStream;

use parlia_ibc_proto::ibc::core::client::v1::Height;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::header::eth_header::ETHHeader;
use crate::header::Header;
use crate::misc::ChainId;

pub fn mainnet() -> ChainId {
    ChainId::new(56)
}

pub fn create_after_checkpoint_headers() -> Header {
    let raw_eth_headers: alloc::vec::Vec<RawETHHeader> = vec![
        create_non_epoch_block().try_into().unwrap(),
        create_non_epoch_block1().try_into().unwrap(),
        create_non_epoch_block2().try_into().unwrap(),
        create_non_epoch_block3().try_into().unwrap(),
        create_non_epoch_block4().try_into().unwrap(),
        create_non_epoch_block5().try_into().unwrap(),
        create_non_epoch_block6().try_into().unwrap(),
        create_non_epoch_block7().try_into().unwrap(),
        create_non_epoch_block8().try_into().unwrap(),
        create_non_epoch_block9().try_into().unwrap(),
        create_non_epoch_block10().try_into().unwrap(),
    ];
    let raw_header = RawHeader {
        headers: raw_eth_headers,
        trusted_height: Some(Height {
            revision_number: 0,
            revision_height: 1,
        }),
        account_proof: to_rlp(vec![hex!("f873a12023b3309d10ca81366908080d27b9f3a46293a38eb039f35393e1af81413e70c8b84ff84d0489020000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()]).to_vec()
    };
    raw_header.try_into().unwrap()
}

pub fn create_before_checkpoint_headers() -> Header {
    let raw_eth_headers: alloc::vec::Vec<RawETHHeader> = vec![
        create_epoch_block().try_into().unwrap(),
        create_non_epoch_block_after_epoch1().try_into().unwrap(),
        create_non_epoch_block_after_epoch2().try_into().unwrap(),
        create_non_epoch_block_after_epoch3().try_into().unwrap(),
        create_non_epoch_block_after_epoch4().try_into().unwrap(),
        create_non_epoch_block_after_epoch5().try_into().unwrap(),
        create_non_epoch_block_after_epoch6().try_into().unwrap(),
        create_non_epoch_block_after_epoch7().try_into().unwrap(),
        create_non_epoch_block_after_epoch8().try_into().unwrap(),
        create_non_epoch_block_after_epoch9().try_into().unwrap(),
        create_non_epoch_block_after_epoch10().try_into().unwrap(),
    ];

    let raw_header = RawHeader {
        headers: raw_eth_headers,
        trusted_height: Some(Height {
            revision_number: 0,
            revision_height: 1,
        }),
        account_proof: to_rlp(vec![hex!("f873a12023b3309d10ca81366908080d27b9f3a46293a38eb039f35393e1af81413e70c8b84ff84d0489020000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()]).to_vec()
    };
    raw_header.try_into().unwrap()
}

pub fn create_across_checkpoint_headers() -> Header {
    let raw_eth_headers: alloc::vec::Vec<RawETHHeader> = vec![
        create_non_epoch_block_after_epoch2().try_into().unwrap(),
        create_non_epoch_block_after_epoch3().try_into().unwrap(),
        create_non_epoch_block_after_epoch4().try_into().unwrap(),
        create_non_epoch_block_after_epoch5().try_into().unwrap(),
        create_non_epoch_block_after_epoch6().try_into().unwrap(),
        create_non_epoch_block_after_epoch7().try_into().unwrap(),
        create_non_epoch_block_after_epoch8().try_into().unwrap(),
        create_non_epoch_block_after_epoch9().try_into().unwrap(),
        create_non_epoch_block_after_epoch10().try_into().unwrap(),
        create_non_epoch_block_after_epoch11().try_into().unwrap(),
        create_non_epoch_block_after_epoch12().try_into().unwrap(),
    ];
    let raw_header = RawHeader {
        headers: raw_eth_headers,
        trusted_height: Some(Height {
            revision_number: 0,
            revision_height: 1,
        }),
        account_proof: to_rlp(vec![hex!("f873a12023b3309d10ca81366908080d27b9f3a46293a38eb039f35393e1af81413e70c8b84ff84d0489020000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()]).to_vec()
    };
    raw_header.try_into().unwrap()
}

pub fn create_non_epoch_block() -> ETHHeader {
    //"hash": "0xfb34966d5d9fd58249d21ee942a8388f1ae763fbb48fe9fcbf31c633564f56af"
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840356&boolean=false&apikey=<>
    fix(ETHHeader {
        parent_hash: hex!("a296df7568574dc350ab97ad9cb164726fb1e3fe1ab5a041cdc37ff01811a3b8").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").into(),
        root: hex!("f69b69767b086d00457a7e979a3f8c51a9e53431d012a8f4be236f889842d4a8"),
        tx_hash: hex!("0586a56a4e351f08d932d46f1a38d9b4bcd4770a81cb502ce24cf3d29f6af656").into(),
        receipt_hash: hex!("e14ec87d1f73ff2d0ad69517566babaaee6ca8a5478d680de9e3b155a1e67852").into(),
        bloom: hex!("5a3e0241010c3e52162830ec8080b2402948725b48311d88f4f903158c0339075b8680870001d400e2159869c8844011a08588591924920188c9686280e40ac060a92284088116b481d3026d2480d06720312a2c037f8ab2240f52c8b9b6b901544a42340f83ad12000d49adc50498411a840c41c3ba464a079108130818846990d8950134ca70a10b8b1e00100a9f840166054d2800822a27c1dbc9cc8422a0a26000251b9da2c02790c7440e1803c0012c0004008105001b02b6c1230045000b8186468709010a210c64258a47f4c02209a3011182e4136301e41f64e4e8a50670019b0524416aa91946896181688169c9259804400458f1c5004049784ea6").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840356", 16).unwrap(),
        gas_limit: u64::from_str_radix("8583b00", 16).unwrap(),
        gas_used: u64::from_str_radix("14b5ec7", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd54", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b53354c0eea0a18bc91dcb99d1a4c166479f719b145b388e15fef755760cf4a95434289b326ddac10bf7e6f443f90d18b077c37a8af90b01cbacfb86b51f59221501").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_parent_non_epoch_block() -> ETHHeader {
    //"hash": "0xa296df7568574dc350ab97ad9cb164726fb1e3fe1ab5a041cdc37ff01811a3b8"
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840355&boolean=false&apikey=<>
    fix(ETHHeader {
        parent_hash: hex!("137901244b4ac0cd1d037324ec990557658cfd8136d90781180b782bf4b30ea9").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("685b1ded8013785d6623cc18d214320b6bb64759").into(),
        root: hex!("fd14a913491d52eb80d96abc4aadc8c4a7bdef2e9a8538bde474b561a8454747"),
        tx_hash: hex!("266bc8e0fec3974b264ca9d0a93a6889a687573a336245b00ed63ff575cd49af").into(),
        receipt_hash: hex!("ab31c2a6f2f1486851e66331636d740781492641150c633ca6dda996e1b0d3bf").into(),
        bloom: hex!("81a4ca43581c10903a882047a522cc63705828b59f1d9c17108495a0c62c3102dc84317b4ec6d684da8bf657a22315720916ebbad44212916b064a851d66c2d83c37ba683809de562f10a8cb24b1282b38300e58035e8c66446525008362aa380d2a2ca95b021648e9090b98c541a90868512d44b1cc36b418033a5a349ae2668898488b66ae40ac01caa60100334080e22606e5fc86c40aa5998a77858294a2c3c044211e1220a8ec47b7512a1c4ee1126e523c901513c5140074c171146ac6400d6e023d8c55a63d0e13218f6275b3b05431c2592a2a18a34327264616e1bb649818a85e205879b1a5dd700c84d900ea400ee841594249b619241c0c7c5488").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840355", 16).unwrap(),
        gas_limit: u64::from_str_radix("8583b00", 16).unwrap(),
        gas_used: u64::from_str_radix("e826ae", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd51", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5b70e615dc1062b92d9781924690b97a94c45fdd0c9e9732dc1b97741ae8cfb6814cc39ff078930bf493110bf556b55d3b6875dc6594674833c22ec285ab8f65101").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block1() -> ETHHeader {
    //"hash": "0x4cb6c17ab791c239ea2edf8cad10bea4276a72bac792185c68413d8ee73543fb"
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840357&boolean=false&apikey=<>
    //https://bscscan.com/block/25428823
    fix(ETHHeader {
        parent_hash: hex!("fb34966d5d9fd58249d21ee942a8388f1ae763fbb48fe9fcbf31c633564f56af").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("72b61c6014342d914470ec7ac2975be345796c2b").into(),
        root: hex!("0c8e1dba1a952846634f6723f30bb4ed9d75c093cc3237056b260639048133e8"),
        tx_hash: hex!("93d60ed1c8c4bf1538a16a95d44b64e1673496af6a59bae7d95131471ba0feba").into(),
        receipt_hash: hex!("d3314eb64012f77930844351bdaa9fefa64340ed392a567340eec4f535902507").into(),
        bloom: hex!("573e8f37ffbfbf34ff345beeefffde3fbb7a87ef8efdffef7e6bafbfbffbb7f9fafbb39ff5fdfb5bffab7efff7feefe5abffdfff6fcbdbf4fff5d3def7fff3deff7fbfeeb69f7fec5fdbeb9fe3ffffbf3ffe3fe9e7edfe5fc78c57e88eb7ffffee7f7f785bafff3ddeed7fefb9feface7f727fdbf57ffdfde7ffcb77b37cfea7f7d7f9de7ffadda63ece3f72afbeeffdf7fffcfff7ee37ea3f7fffcf6fc63ffbe66b7f6bfafabbdcdf09e5c4daffd77fffffffefff4fa7c6cf972f5f3ffffef7ec6afd9faf4df7cedffdbfffff2fbfe8fb4effd3dfdefb57daeb4eceef7fe6cfb97f2cb3dfff6ff9aff9f6e5d3ff7ff64b6defdecfa8fdfbb57dfff5f6bffff5").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840357", 16).unwrap(),
        gas_limit: u64::from_str_radix("84fe2c6", 16).unwrap(),
        gas_used: u64::from_str_radix("1c4b60a", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd57", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5f7fd13e9ce4b690ac9caa4946e5cd74e60c4b8479904a87bf389f685a4f9652f2b88e687434326c9a6c6ecc86b2814e7a36ed6e056f829cb58756799fee4ef3a00").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block2() -> ETHHeader {
    // "hash": "0xeb76cacbadce9f7a7114f32cf1bc9c617408111b5e4349e2373f9091bc6c158d",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840358&boolean=false&apikey=<>
    //https://bscscan.com/block/25428824
    fix(ETHHeader {
        parent_hash: hex!("4cb6c17ab791c239ea2edf8cad10bea4276a72bac792185c68413d8ee73543fb").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("733fda7714a05960b7536330be4dbb135bef0ed6").into(),
        root: hex!("fdde769b21fde469f42af34173dc2c5b467f15b344a0d187de85221ad6944d78"),
        tx_hash: hex!("7bd8adc284d1a805bb38e15f7e75a5943daee119dd235370a0b24239a9cf10a3").into(),
        receipt_hash: hex!("a993156dae55e5b1c021ff51989e70bdbcae8e26c931e36e06108060874fc66c").into(),
        bloom: hex!("ff3e7af96cf85eb40dbefbdebeefd23fecb77736ae99968f7db5b9fb897f5739ef2164fb5edf3a6e9222733fcbc666ec23e9baff6a6ec3eeebedea42d9ed7cd50b6caecbc42bfc32ef766ffec8af9bb9bc7ae94d6fd55e4e755f37f4ef70fa2b6d77c0fe1e82226b70cfdecaf75aeff33ed6fefb6fef3c693fad4a9379b63effb7ebbf8defa5b94f95fdffe9edbbde98e83dad0f5f62c11db529ee6f9ff778ffb287bb3f1eecffcafade6cdf0e3b64eb836aae75533affaf3f9ff47da9f25e7be39767437771d36fce7513212fb61fb123fbeb66d32bf45733c1a5467faeea66da7ce6ed46f1d668fbeddbfecf9df1f27f9767caf25ffc4f7e8adbd16bba79fe").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840358", 16).unwrap(),
        gas_limit: u64::from_str_radix("85832a7", 16).unwrap(),
        gas_used: u64::from_str_radix("2b9b7f1", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd5a", 16).unwrap(),
        extra_data: hex!("d683010112846765746886676f312e3139856c696e757800000000005b7663b5a03d048e7fa6bed86346930f5189ee72c9d88dbace785f7a61063c51a645284a1907671695160d2dab037e12ce514a265906bf05b9bd6d1f0f2cf25cafb6891b00").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block3() -> ETHHeader {
    //"hash": "0xb21b8d8ec8253df4da078fac60b24978d6efab1e7e738665b8d101ea8868f4b5",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840359&boolean=false&apikey=<>
    //https://bscscan.com/block/25428825
    fix(ETHHeader {
        parent_hash: hex!("eb76cacbadce9f7a7114f32cf1bc9c617408111b5e4349e2373f9091bc6c158d").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a").into(),
        root: hex!("42daf0cc8774f52215cbc72e90a4d7a75354cc7c2a944c36c88f01d272b9e927"),
        tx_hash: hex!("7bcd94438e21c5c55c9e298ff5a16b9d15f73d0d4d5c93bb1f45285a2017c75e").into(),
        receipt_hash: hex!("0a59c26bc0d1e5b0f064584d21ad6ad41bc17fd5ecebecd373f2a81149187339").into(),
        bloom: hex!("0d321a4614c8d532200830c7b5645c3ae41104a08f1d47067a3f0b0030843d237f02d12c7f2514168751bba70442604d09316208160362a2481ae04c24fd2a968494c7418c0f12840196121948e15322ad10019601570d1ee1149592df60af802a33303d1e0e6261543d2eb64b018c0a3a416877a14e2e944110c0183009b22b10ca3b4f228a91a6528916114a10485930bd97a598a2284e2590b24824d8abbd82fb3064527692c746136ff03b2e56091c3ca1902880088018024e2211f05158e309e5032c5a0786a08823a1398633b321563928119a3d3683a5502e3055f28416f73d99ce2400688348bb37342301c5b26b76a873c6314884e90c3d7120c8ec").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840359", 16).unwrap(),
        gas_limit: u64::from_str_radix("8583b00", 16).unwrap(),
        gas_used: u64::from_str_radix("ad32da", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd5d", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5c3414aab3839e62006ad71c62771cdc45a45574f31bc2e3cf5ddb339ae2c0e00159ba335c0a4141a2ce86ab7ea22430ecc5141fe92fda1ec628f2ad914bff4f000").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block4() -> ETHHeader {
    //"hash": "0x338f33d4704d8dce1ccf2122a81474e40e82e4aced63a0e2109ad1975df75f25",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184035a&boolean=false&apikey=<>
    //https://bscscan.com/block/25428826
    fix(ETHHeader {
        parent_hash: hex!("b21b8d8ec8253df4da078fac60b24978d6efab1e7e738665b8d101ea8868f4b5").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73").into(),
        root: hex!("156fdde3908229b9191ce1067478a3a69f28504976effee82bbc7bd08a3f78cb"),
        tx_hash: hex!("333d315b7577e1436079df92ba91207b888e1f86f8e0a4c4d724cbe3930e268f").into(),
        receipt_hash: hex!("e89e29aa09f1528569a2dc9b35db624ac330854728c0972a25064d275249fe9f").into(),
        bloom: hex!("402e039d31280458a80c0066810a206c1c1c602c4915824871c601b12428f1480ca0ac2444009101c2813170a180034c00014a220a840c031808ca87086f16981c20ca5308011266914244f80b831e60287c0a2842de080660440515b424d91c612804a03fbe2248401128a80106c8450a8025e9034954004481a4193b0108aa0a4a5b3f248bd92450e68230087091441135040714a0122cbdd9c7568da20060b3d0927310a2b4008d2865c9074012c890284250200e02082b28982500d0007259a0008a2518514e15a694212d86721037112d20890e28112161407ed988e840c679288288bc54282708021491009800485484f8c140404ca40b0a662a4040a0").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035a", 16).unwrap(),
        gas_limit: u64::from_str_radix("8583b00", 16).unwrap(),
        gas_used: u64::from_str_radix("72ac60", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd60", 16).unwrap(),
        extra_data: hex!("d683010112846765746886676f312e3139856c696e757800000000005b7663b5215f34124ab6627556b46f8c9062cd9e84801f5538152d5e2875211985c45efe212ec1845e513343caf641cb1b3c6ee54a4bec9d2ac7a5695062acae20ebe97301").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block5() -> ETHHeader {
    // "hash": "0xd878aac89070a61023408927c1159693f9f5120afe4350f302a902266cd8ab7f",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184035b&boolean=false&apikey=<>
    //https://bscscan.com/block/25428827
    fix(ETHHeader {
        parent_hash: hex!("338f33d4704d8dce1ccf2122a81474e40e82e4aced63a0e2109ad1975df75f25").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("9bb832254baf4e8b4cc26bd2b52b31389b56e98b").into(),
        root: hex!("f80a9f51be475d1d8c9fee0cf59344be19d1cbf7c7837a67a5d2edc2509409a7"),
        tx_hash: hex!("da065d7a70e35bc93aa60d2da20986390b0d30b9311576179828403bd1abbe73").into(),
        receipt_hash: hex!("438131fbd3edb2083e629c2f42cb24e0a21fb6075130c5e8c6282deaf7f92488").into(),
        bloom: hex!("f7e7eb77ffedfffffffbb9effedb6befefff7fedfffbcfe7bbffffffabb0fbfafdbddd7edfeffe3f7ef3ffabffdfbf77dfdfffbf5efffdd7fbbff7ffcffcefd037fffafe51f7efff97fddfffedfcfbfefbfffb3fffffffb79dd7d1d2f3bfef5fffeffeffeffbbfb7f6b77fceffd77dbf7ddfdfefefbef5efbfa3dfbfff7ffebfffffffcf77ff7effffffffee7c6fffffffffffff35ffdfe9f9d7d6fddced7d73bfffff7bffff7bdf7fe7ffbc97fbcff6d4fff7affdfd5dfdfffe7fffb5bafefde57ff79f5edbffb6fcf6fbf9fbfffbbffdffeffdebffbbf2cfbfbfafbffdfff6fbdbddff8ceadffeb7feffefb7e7adfffffbf7beefdfde7fffef7ee7b9bffff3").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035b", 16).unwrap(),
        gas_limit: u64::from_str_radix("84fe2c6", 16).unwrap(),
        gas_used: u64::from_str_radix("2bc985a", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd63", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5d118d1852ff47de7fa95ae52050b954c56d2321ed23c2c824a2bba7da95a3af80c6bddecdd1b211916a690e68e49b25aa79df960070051091fc05efea51b6a8101").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block6() -> ETHHeader {
    //"hash": "0xf1c471f8db78111be2ceabde143b3b6df5005dd9cfc3ac70cc8676c6eb675d93",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184035c&boolean=false&apikey=<>
    //https://bscscan.com/block/25428828
    fix(ETHHeader {
        parent_hash: hex!("d878aac89070a61023408927c1159693f9f5120afe4350f302a902266cd8ab7f").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("a6f79b60359f141df90a0c745125b131caaffd12").into(),
        root: hex!("d697e01142a8f704dcc2f8740c96c462a0766923a6bc5cb4801d1460b28e1e66"),
        tx_hash: hex!("35703d405011fb06914aca0f69215349c32d5252fa43d75124ab7bf23b89e8e2").into(),
        receipt_hash: hex!("ccb0007891509c811717b1e5a3cd5690ea0bc44a352bb8c4c6f6e426acbd4d1b").into(),
        bloom: hex!("8f232b83b80cda33854530c5f5e73023350a27413f568f5631eb45c468011111715628d128243554cf4af3bf8602c727493ab10346ad10884f2c52e4de750e54a929c0129e43663537fb82de429e102ebb5ce568fef80783a1df5464d470ebf7032f58f686cf624b654db9bce28888641ac80645a56a77c6096006946d4267ca1f307b7132ce37763ce95b7644502bf80067e4453a26c45e3aa39be96ee14ae8a2e03d59889730db372b45468a4b0bbf24cc8d022d65a84c8a32ae29e0a496c78bab61a6cd9e890374a64061aaf4f570208379dec780a69e9b51400f1f34e80c155ab9b02dee723b1b58a638b6c50470f7c23cfcef688969ba042f30785561ce").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035c", 16).unwrap(),
        gas_limit: u64::from_str_radix("84792e5", 16).unwrap(),
        gas_used: u64::from_str_radix("16255b2", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd66", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5a93e83672382250e0d5d094fbfe6bdd7bc0b7beb07f97aec2d741031f602e08b1edb12840d6d6a0fa56c41769eb968def0816f5e58cd46dcc21f36fa3a79dc7800").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block7() -> ETHHeader {
    //"hash": "0x3673eb3fccbe533880115c030a6f2afdaf2c0527f066c3f094dcf695206bc1ea",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=184035d&boolean=false&apikey=<>
    //https://bscscan.com/block/25428829
    fix(ETHHeader {
        parent_hash: hex!("f1c471f8db78111be2ceabde143b3b6df5005dd9cfc3ac70cc8676c6eb675d93").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01").into(),
        root: hex!("ba012acefc3c435cf5a0eaaf1654ed6fad55fe9d588f0b111295692f0c268890"),
        tx_hash: hex!("b96cd061d87f0b6c872c18df0c6771029874a224be813499dec759a3e710398d").into(),
        receipt_hash: hex!("a8061bc893ffbde0a28b956e703fad02c51c880f48ce6cf234951de18f4b2026").into(),
        bloom: hex!("d1b6861f8ccc19d02485d9efc001e339875a26421c31a408e49311130e613541feb6102668d092a16e65417191848024a29018b1a3dea5c109c807696960a3d404e5950a49eb95420189484d22a96e66b314ce72c97a2a6910c494c1a069c904c0c022248e22ac10244541b823c4d8149b0d4c5ba82af4019139909b33801c0d9d8c650d70da18c4108492864120119600741ce7b75119cc13059f67ddcd402493242c9f50d048125012314153a83a099b6804280827224477422c2a0084330405d0bd13349c33c29222b4254c42774962c323843b2f2655e30d624e0610b0006079bc90c820f029919922310832400010148d890070665cbc5d00fcdc8de486").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035d", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f4b54", 16).unwrap(),
        gas_used: u64::from_str_radix("daf95e", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd69", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5c03f3111140eb42062efefc2d6d415902d5d936f83f87bb924711f45960845842ab32e7cbddf8f4180703038d292a0e4dffde510234d48dd766dfd93f9ef319c01").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block8() -> ETHHeader {
    //"hash": "0x442910010b4286ed4b023ea5a9e75cd80dbfbf894c553706083eb69dc9ac58e3",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184035e&boolean=false&apikey=<>
    //https://bscscan.com/block/25428830
    fix(ETHHeader {
        parent_hash: hex!("3673eb3fccbe533880115c030a6f2afdaf2c0527f066c3f094dcf695206bc1ea").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4").into(),
        root: hex!("537f9eaa41f3ec478ce83f125b36d388e212f4d6fce556748ca2b500a4a4f4ce"),
        tx_hash: hex!("3d95243af1f6231385cb5f366705ff2da1fe36acb68db102419bda8df5128ea2").into(),
        receipt_hash: hex!("a9d2e0060770b08be8f253bf6a29ae32ab0f6dbe0888b9cbf553366075c4529e").into(),
        bloom: hex!("00621f0406910f7002ad287f8dd08e33719e20bc6c18b3a3190125614441916277641ce008529712010a3315c004943f63845a101b2f0781081ff24e10f50331d288dbe284a16ca049edb55f22bb80382818002811740e8455ac8597ae2c8805010ec4210a06a70802170faa2159d8280ad2724039ed64805cc108718893008308f98d462e98142ca4d3bf0080000e025b3724c71086116b259dc2758c86cb25a24c14715dfa31ba8c2660600e0a0023154ca0a4001522e6a2032c2073503443410904c73700190295a2b5a18b9316022940478191ac27dd89410486d114e012295510962da133280544a732d509642ccd621e830850024033109160453460fc").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035e", 16).unwrap(),
        gas_limit: u64::from_str_radix("8370c0a", 16).unwrap(),
        gas_used: u64::from_str_radix("a6d504", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd6c", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b530a77fb5e6ba8df32957de6224f8bb74fd79dfb4f535716de7b6ed799128f2d63a53daa841908b01f6fc5a5226a74de51407a226ee44ce02a5f8a2517d518b3f00").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block9() -> ETHHeader {
    //"hash": "0xc3daed0540ad771bd41ff3b8807e9ac5ae356a3766caf9000a7662ec71e5606c",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184035f&boolean=false&apikey=<>
    //https://bscscan.com/block/25428831
    fix(ETHHeader {
        parent_hash: hex!("442910010b4286ed4b023ea5a9e75cd80dbfbf894c553706083eb69dc9ac58e3").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("be807dddb074639cd9fa61b47676c064fc50d62c").into(),
        root: hex!("fdee83d62256b8cba3d7c301ca69f5b025b92a8ad7145a0197b6361ab1b269cc"),
        tx_hash: hex!("9036ace500073ab5b1d9171d014425e1f5eb46243caf5f681c67eaee8b00e09a").into(),
        receipt_hash: hex!("0cc18399e68970e5613ae2ff16f32c3b7a02f13ac4659b861617757fc895755a").into(),
        bloom: hex!("9426936d99483c10c41d11739058247823b04c64bf15548adb5603e03169310024485842b480f340e3491b8a0e02f9243969d01209632200e99b4e349ce550cef020f29007752a2c11a6c27bcdab42222a90951017779cabc84d0596a9ee81665c3719fc938aa34124812ed2a2ac89793a91a0c7a1cb1fb588669010140a9f231e160b013dabbc2a9e9d87930a31ec9be83f1ca7d8ac7c2a6119a35f8cc12ba38289503d3d0c49c0249965530f2a045bd13c9990b48f392018907a25406a19cae11804a60f5c214a310a25333d8614116b6e794da1a038bb0063f14e5211eaef0832099341256348212ce69324035c9ce853a43f47c02050a24b1f1e681a40f5").into(),
        difficulty: 2,
        number: u64::from_str_radix("184035f", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f4315", 16).unwrap(),
        gas_used: u64::from_str_radix("d2d0b7", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd6f", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5a32f8b73e44e16e8e44a31298a3a03674e760c41c03f7e30e11b76cf096bc4510c8a9fb259573b5d9e90979038a3d55ba05ed976054868ebe3289ea947b6d03a00").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block10() -> ETHHeader {
    //"hash": "0x46af0886d2f6a8470619a3596fecd7f025d2589a04e08f805843b78402eae008",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840360&boolean=false&apikey=<>
    //https://bscscan.com/block/25428832
    fix(ETHHeader {
        parent_hash: hex!("c3daed0540ad771bd41ff3b8807e9ac5ae356a3766caf9000a7662ec71e5606c").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("cc8e6d00c17eb431350c6c50d8b8f05176b90b11").into(),
        root: hex!("f06c333c4f68da6e3ed0aaf6557cef8e3ca4e90f000ab3c32d7c0be69d4cff60"),
        tx_hash: hex!("f2b002fbe7ae471d7664beda42a2e1777c832c3791fbe8058ac07c939a8a7ebd").into(),
        receipt_hash: hex!("2c45fea0b874a51a5ccf859a20c73beceaeee159e484aae2a0db0911a7ccb0d7").into(),
        bloom: hex!("fca2822009443c3c4a1e424ca40000b8604501083f168b0c63312140080b90c02010b01040821010451070b0202002093123122111175211490880071df79052d164ab050101c432d186616903e81161283a2a29275c0a04831e15348620cd05aba010640eb26420200120900500ca5d0aa31a49e1482c8488284418592283120bd9f14362cba00455fa064408103810433714e73208d97c4181c2410c060aa25fb8994010544104880041590ff4ced2012d0a02804e04b42ae03b44000188410108045a848c0912042080b188427a10b8c2114401a028333141001e0180a210407880a005e0185b33e250c440618502c00e06a32090484180005a602a035008").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840360", 16).unwrap(),
        gas_limit: u64::from_str_radix("83703d3", 16).unwrap(),
        gas_used: u64::from_str_radix("96bda7", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd72", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b59cae7eb84b7110f150337b12873b46b9137670da834199a0f44e3f3710f1e7c101f16582c43d2e5c1dfef4467ec3ae6c49dc4f45ff2c54623d87e726dc97e9e901").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_epoch_block() -> ETHHeader {
    //"hash": "0x66eef8f9b1ed19064a56d366288e0ae2bbd1a265cdd9891d42171433b2a3f128",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840340&boolean=false&apikey=<>
    //https://bscscan.com/block/25428800
    fix(ETHHeader {
        parent_hash: hex!("a4336fd8a6445e66a3e5f5230b2bc4989f90b27105cceda8d3c6fb049ffc3909").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").into(),
        root: hex!("0d260c07d69e5b74ca30f8b0a3a2519e8c0af486c23b508ccfead58c09bcb1a7"),
        tx_hash: hex!("06567847742568122d2ed560275e691f893acada867b4a490e18d9bb17b0747b").into(),
        receipt_hash: hex!("faacbaa0d78a2dab71d8def4b3a6f2c8b66a92b9f2035ce8f4ffb524fd2bd578").into(),
        bloom: hex!("6f6f3315f3cc37514a2ca6c4b4e4195534022c22d8b90888a0f4bf2790b0b38e92a290445dcbd4d9cba30a58ee56092f62d1d96b0eae1a017c142e4a2b7687e28429273309e331e6c722c0eb8aa91625a8d8ac6bb9dd1900915ee164babcd846448813e87b12f34a781720e20c008e304a945cc59ff91fb00ab27850b4bd57aff249e17d66b9b448b3c89e9c051890d7102c7c97ff8ea228ed03a6c1ee976af6e2843047b2c8f5bf715035199e4e657c140ce0fa85cf8b0db200f83fb74658cd61e38de2341767b307f5a16f6dc2b2026a7fb9fe3976be925f432bbea2c5fde3eb3ed6fe41b561eff949406a8d1184cd458f0ca9cae5387be64f3b8c3b45504d").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840340", 16).unwrap(),
        gas_limit: u64::from_str_radix("8583b00", 16).unwrap(),
        gas_used: u64::from_str_radix("237c89f", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd10", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b52465176c461afb316ebc773c61faee85a6515daa295e26495cef6f69dfa69911d9d8e4f3bbadb89b2d4c407bbe49438ed859fe965b140dcf1aab71a93f349bbafec1551819b8be1efea2fc46ca749aa161dd481a114a2e761c554b641742c973867899d3685b1ded8013785d6623cc18d214320b6bb6475970f657164e5b75689b64b7fd1fa275f334f28e1872b61c6014342d914470ec7ac2975be345796c2b733fda7714a05960b7536330be4dbb135bef0ed67ae2f5b9e386cd1b50a4550696d957cb4900f03a8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec739bb832254baf4e8b4cc26bd2b52b31389b56e98ba6f79b60359f141df90a0c745125b131caaffd12b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b4dd66d7c2c7e57f628210187192fb89d4b99dd4be807dddb074639cd9fa61b47676c064fc50d62ccc8e6d00c17eb431350c6c50d8b8f05176b90b11e2d3a739effcd3a99387d015e260eefac72ebea1e9ae3261a475a27bb1028f140bc2a7c843318afdee226379db83cffc681495730c11fdde79ba4c0cef0274e31810c9df02f98fafde0f841f4e66a1cd6507144132e0691ce5599d192061f5b9fc5d163a85e99f9776f204bee64c14af6aca6826d158ef20b6737df80d9579b094b7d0145c839c98cf502eea728d632800").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch1() -> ETHHeader {
    // "hash": "0x82629d5d116d8ef99079f7ea8c7bf8b522bbfc13c6f77e9bbdeb2de3c5d897c2",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840341&boolean=false&apikey=<>
    //https://bscscan.com/block/25428801
    fix(ETHHeader {
        parent_hash: hex!("66eef8f9b1ed19064a56d366288e0ae2bbd1a265cdd9891d42171433b2a3f128").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("72b61c6014342d914470ec7ac2975be345796c2b").into(),
        root: hex!("aadd9ee88fe8274e520affb0641e0e6574c51c2b0e6e4f3c3d62b1dd41c03c70"),
        tx_hash: hex!("0d459f85b3cc02d76d4a92a00923fe07ee626fbefed917e74914e5dc665ac99e").into(),
        receipt_hash: hex!("34480f79dd23f782c69fff88d51ed3e9533ed22a164b3bce6d99a74a597a7927").into(),
        bloom: hex!("ef7f4ffdbe1fdf753d7fa17fdaf77d76bed76f6bdffadfe4f1f73f3eeb24fd6fc7fef9d397f15c2bdf377bff6b7797364d5b79957efb30ebef7bd75bbbe5ebeefefab8f63bf7772d53b7faffa9edfaffe9ffea2bff7efbbbfaef86dfb97fd96d58f79dfd3ad6b7f7ebf966f699569ab37feda87971ff4c7b1e76d7f9dffacf7bfeff7b6d7ebbe7a826eb377fbef9fefb9e7f1eef56c2afd9ffb5ebebdf8fffabd3eff958ffbfffdb3f95f8ffbfdf4bed5beeafbb9d489bfc7e7affffbfd2ea3f6c7bd776a79fdff6f5bf7eed3b47ff1d3f65fddeffffe93dfd739bbfffa7f9e7ff137782afab1fffbbbb5d8fb72e6b32fbfee4ccdcca756cdaf7ae663f7bedfd").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840341", 16).unwrap(),
        gas_limit: u64::from_str_radix("84fe2c6", 16).unwrap(),
        gas_used: u64::from_str_radix("253c4e5", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd13", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5cb4dc08189ce734e74401e27676e5b73f01d2c0ba801943f2964e0ef23a74b9d4b869cceb9e5b9c06db181c0410ee187abcd56235f9831ec9ed892b6f034016700").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch2() -> ETHHeader {
    // "hash": "0xa103089902d6f8cce2736099a01b3f81c9fdccb24f52a10782279f9a138bf87d",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840342&boolean=false&apikey=<>
    //https://bscscan.com/block/25428802
    fix(ETHHeader {
        parent_hash: hex!("82629d5d116d8ef99079f7ea8c7bf8b522bbfc13c6f77e9bbdeb2de3c5d897c2").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("73564052d8e469ed0721c4e53379dc3c91228930").into(),
        root: hex!("3de27215dca321ee00e7ac5301c15f7c594e4b49f112087711691efdab82736d"),
        tx_hash: hex!("91eab0e8595f54e1b80a3f72f247fc3a959269aaa49fb455761407675e5d80e3").into(),
        receipt_hash: hex!("fef439b1a28ce8812194154c20d9a38c7793796f3895a4115b292974ac90b6ca").into(),
        bloom: hex!("44222b4cc0c01054220c3066a8500b400441e178b8b0c5000053292670ad172a34a041a41f084802fb0359f08b1011840748381400761081d928a6100a7602923420c2a1487572024169925900d122302cb4aaa71e543208c3ce4447e021ec4578501be00a1270212d2700880340881a5bf824349198440006b110b302891e9f105881b3a0a9801c058a2748009003b0102e3591400010c8832ce2f45ca20ae19220004101d380234a0078f16e00740452ac04a340b8058cc20359c5530884624100854a040001060144d629485270043943601005b024504545023f1118ff80451037faa122582329e9022000424020d46280a302e53059224029000c0354de").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840342", 16).unwrap(),
        gas_limit: u64::from_str_radix("84792e5", 16).unwrap(),
        gas_used: u64::from_str_radix("128e9d5", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd16", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5376bb80dc6bfe9dc7d064bee002761e804e4bcd62d93d109212940ed4ea550152e59258999b780c09f8756ba01561185fb0ab1c9f37e9774b587a6c8f9a892f001").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch3() -> ETHHeader {
    // "hash": "0xf0bc5613fa310380c29fb809b22442f08aae822ce92cd7a22b434c954e12c51f",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840343&boolean=false&apikey=<>
    //https://bscscan.com/block/25428803
    fix(ETHHeader {
        parent_hash: hex!("a103089902d6f8cce2736099a01b3f81c9fdccb24f52a10782279f9a138bf87d").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a").into(),
        root: hex!("c97ad156641156e1fe3d52aa2e6b87e1f1cfaa7cefbe7eb16d643393645c5268"),
        tx_hash: hex!("f0dada83e83f4ee6ec26e8cb1e89cd49110b26008723b6955d13995a0cfc8a4a").into(),
        receipt_hash: hex!("eb442bae926eb3d4220af7447da32295a52701bd99997939a3578633a7a7a961").into(),
        bloom: hex!("cbe6c355a0105fb52f9634ede1c0d152ccb9ddc19c3b88c1b27193e66c187f0332811081c110d553ef013eb0b04b0d20a90470a6612a31bcd8dcf7937efcbac00664b4541cc96e524f15857986ab3ab1e4384928c374a80200f494608caae1d51634d96cda8a33fbb90dec88031d89a02bb74a43a92a3d47598514d39cb6d323887d2a29b1ccade406d9aa021c322e90007d0cef9111b21bb1398a71cdc9a874d683397311cea7165794e65cc71acf67424e40a13144e4074a18f53c8828236fa8a338a3341b2f862a242d692bc63ac13560efd603d4383e45fd786e2440ea66d456df9281bed88b232c8005088790c8b017362cd0441c59b68e621c8b87e0fa").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840343", 16).unwrap(),
        gas_limit: u64::from_str_radix("84fda76", 16).unwrap(),
        gas_used: u64::from_str_radix("1042e2e", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd19", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5ebe98229f0e3c9570720f330d9c58d97c3e6136f184f66ad815995687910188f612307c441bbd5c389fadfaec9738ac59fb6cad38c669da4ddab8125958f525000").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch4() -> ETHHeader {
    // "hash": "0xafeee17276a703c50b6c0c9ed22e270bacb9b4247a4b6d5bebd08e7cc9c9af94",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840344&boolean=false&apikey=<>
    //https://bscscan.com/block/25428804
    fix(ETHHeader {
        parent_hash: hex!("f0bc5613fa310380c29fb809b22442f08aae822ce92cd7a22b434c954e12c51f").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73").into(),
        root: hex!("57c384fc67a569d7fca5963df3e293612290ad2b4c8df55165f11ca2b121609a"),
        tx_hash: hex!("6eaed635d076aee0f875216e7c9493827a82953dcb8f0cb167b3161f2d57882b").into(),
        receipt_hash: hex!("4fa6d8b684b6595661db73e2a24100c9e3bfa3c0c846fb6ae00a30a34f6be5e8").into(),
        bloom: hex!("8f3cdab681b971fe6f09384ca6e342cbb4fe49bd815cf608f02b21f7740419365b1b98c14c577c2fe3a11d7cd016267c31052452028a3282b31cdb70ac6c22daa5ffc75d0057b2b05b16cd19eae938eb29b00a62d35588ad8007485cfb22bd248b8c36672a6387a26b7daad9e9b25ad90a54595b8b8d47fe1cb9ea581b5e98e3409aa709fb99b0e899c95f2d0732bbaa947c84a519aa2e498550be659e9b99fa8afc73483084a3428aa4edcf8a2c1d58269d05a3a9fe38043b9c9c419d504064a1e16c4ec5d75913605b48f158c278d9eac82f0459d8fc550f07563f7604e14762b493c126e2c008738d6e906561ac11c36d75a03361775c761dac7668b158c7").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840344", 16).unwrap(),
        gas_limit: u64::from_str_radix("8582a4f", 16).unwrap(),
        gas_used: u64::from_str_radix("1383959", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd1c", 16).unwrap(),
        extra_data: hex!("d683010112846765746886676f312e3139856c696e757800000000005b7663b5460a5703a428e1767a533acf7798c549aa18eb83807ea41ab537e734bcde4a47793cf63b55a670db778eb8468fcfe6afb831da3b2ad5fc72c9ae43591312e02e01").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch5() -> ETHHeader {
    // "hash": "0x3eadeeede43061313f472d165e25d17713488a69ec947045b4e1456a14799c29",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840345&boolean=false&apikey=<>
    //https://bscscan.com/block/25428805
    fix(ETHHeader {
        parent_hash: hex!("afeee17276a703c50b6c0c9ed22e270bacb9b4247a4b6d5bebd08e7cc9c9af94").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("9bb832254baf4e8b4cc26bd2b52b31389b56e98b").into(),
        root: hex!("4021d1649441ebc3eea19af316019e40cfa426b42514e454a5a5b99cef720069"),
        tx_hash: hex!("1d06644fed25508e98ceceab0cd28af547d043c04cb9d3d6336fb7f9aa9c5641").into(),
        receipt_hash: hex!("3d979f4f2663bb70246221563ad0e7f75be0f4c2d80bc3ee21997b925c0abdfd").into(),
        bloom: hex!("fcfa66143effd9f3dbbfbce5f3d25acf77b9ebff9159eff6bbf9b3ef6d7a93ebe5e55bffb5e3bc9dbfbfbcd95356e1d0fe0cbb5f1be6bbedcd3ff6e3ff7d33f3b5fefeb16d3bd50da5a9e9ffe69f7aee383c5a5e1cfedf3ee05f7552bbbdf9cfefbebbffbb3ef6c9d34731addd5d89627b0e00e8efcffefcdba1fe9b72febfcf3ebe23ef67bddee40fe2bf25fffbbfb8ffefbcf5b4b697eeb535fe7de9bebe39dbd3f66bd6bd8e69f7a7fb4efffafdeee6de9daff5d5d1f9cfeaff7f29bbebfee7571e667f9ff3d7dd7899776d8bfc9f7d9ff2f0cf3f2dff9d5bc25f5afef8377b5466aea7f3fb73ad69f10f87c65b6bfa5eafcdf7bd33ce4efef68dfdf552fe").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840345", 16).unwrap(),
        gas_limit: u64::from_str_radix("84fd226", 16).unwrap(),
        gas_used: u64::from_str_radix("1abbbed", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd1f", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b5e75520eb46384648775f1c1cd3eced340dc8bf15d777a71e77ff4acdc4b9d4330b0d44b3be377de3d6481dae9be29bacd6fd02519c65ccdd393217ad0011b79900").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch6() -> ETHHeader {
    // "hash": "0xc4e00830e3a61723bf5e3fdf01dc7efc7f4f7474cf1b2c76e743ebeb318e85bd",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840346&boolean=false&apikey=<>
    //https://bscscan.com/block/25428806
    fix(ETHHeader {
        parent_hash: hex!("3eadeeede43061313f472d165e25d17713488a69ec947045b4e1456a14799c29").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("a6f79b60359f141df90a0c745125b131caaffd12").into(),
        root: hex!("a3d50679112967ca1ca43e7eca7e5cbd8c6e47bb8be26d32f51485f3f10dbf31"),
        tx_hash: hex!("96123cea3eed77cdfd66b46d0a580394f8ab0ad6bf97fac74dfcf8f97c016ffd").into(),
        receipt_hash: hex!("d6f9f7d76c3b78f7f916f38a6e81083b1c610bf5ffa9c7f7244f528159d2bc2c").into(),
        bloom: hex!("4236a2079c34d8320f20625ef147c995f0c33a914532651434df0976ee02379d54e2380634c0906e13871473245721266fc01a6e4616c433344ec3a2daf5b23461d0ce1508f14e0a857a0b7d07e0b83564f6a5a121573a82c6e63c60f02ff28be1245ca7aba204052e272e8027818807ca182fe5b589e71ad8650a5b3883160c937973cb7ac03964789482d8c8104bb0f06c0497d260081ba911c3c3ad89183697bdd5615def625f6c2325c8025be844bbc811f6c8205d901adaf0b94094a322a1b00e9b7d9127c69043c4e5288e3965a9e163091f3a26146d7500f63898a8286c148ba4e42776781b6af15c301956105760ac0e2b606c7c22121226046a0a4b").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840346", 16).unwrap(),
        gas_limit: u64::from_str_radix("8478255", 16).unwrap(),
        gas_used: u64::from_str_radix("db830a", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd22", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b518dd9fece9daf65f463e8b8d10548f9fd91fa9839c0f14ab6c8e2af07e530d3628f912536c0d0d38b85b85eea06ac025208b134a739a35fcf65b01614fde925a01").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch7() -> ETHHeader {
    // "hash": "0x4a570dfdcedf9b9d853f2c238844796c5db499e4f361eb58b97e926d67f33e93",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840347&boolean=false&apikey=<>
    //https://bscscan.com/block/25428807
    fix(ETHHeader {
        parent_hash: hex!("c4e00830e3a61723bf5e3fdf01dc7efc7f4f7474cf1b2c76e743ebeb318e85bd").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4").into(),
        root: hex!("fc8c4735f497b6739c686faff3395340aa35d3413cdee0b9e46d242fd3a7fcf7"),
        tx_hash: hex!("5ead0b58c3f20494b46fbbe30ba2789b68c8f97b53a2a0afb0a20fa3614c5f05").into(),
        receipt_hash: hex!("4eac95ea6c5cb3c1e29f907fb22de21208e71f20f6a67ae4e058dd6d0267d898").into(),
        bloom: hex!("ac2c3b60240eb8911289f04e80200982020445f9695da6ac724345c26060d7a62c8880e829861410230639a4000101312021a624c28416c051104403087472d2aa317c733403523243328c381e885625ee111a22aa6cca8ae40619c89024c92a505f102d1a0b6464406d3aaf55608b633e50e547b04c543592f0183104e018228aebe3a022bd106ab08116d10836ee9020360c0520621aec21b08a6348931a2083a1854c10dcb3e79902f65b17180a0c12e801a04aa980859a898c5f8111ec80ab92ae42848911be07e414218b823200e4b43345d1ca34329553848e8220ec4c28343a9b45f5486f8b5821804000086c415a24da0378886a07a000003844c1d6").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840347", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f3ad4", 16).unwrap(),
        gas_used: u64::from_str_radix("9fc8d7", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd25", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b577609d164726e06adec54cdafe2677ed087f3acd45cfc89b37dd424c0064cbdb59d5ec4414dc81831ba55b39b5e9139ad13be608f60787a4b900293fa808054301").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch8() -> ETHHeader {
    // "hash": "0x678572fa9b9f6a982072a6f861735da54fd6a538d20faccc013ce129512eca31",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840348&boolean=false&apikey=<>
    //https://bscscan.com/block/25428808
    fix(ETHHeader {
        parent_hash: hex!("4a570dfdcedf9b9d853f2c238844796c5db499e4f361eb58b97e926d67f33e93").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("be807dddb074639cd9fa61b47676c064fc50d62c").into(),
        root: hex!("2095de30fd7de965a6a6a0e6f845a614b072adbd8f50a4e8d914ea06e0782fa6"),
        tx_hash: hex!("0ab9fe23645f1da8ba31c22345f6d6ff4c20a54f06148ed9397ba74c6000d292").into(),
        receipt_hash: hex!("99c2dd903e880441f9b5f545296a5de0314a290c8f4f03c7cff84237b46d60db").into(),
        bloom: hex!("852c12120520d4100e0cea54c242d131a6c204d7165014c8799a97c70675fd2d7f0895564d0cb716cba0bc7a588df0eea8bba048046a03046c38c5465e77abd82929f6db85294fa6818e826941e214bb61794668dbd50c96e585c40ae527f900098a5ae79b06e207195558c601245a694e506b75a79d44be692dc07408628f645eafe5776293a82455e1a603ec341cdac8353c877f0a983a2d31bed46c8b3b36eafec1e892a1bbfd2602e14e8bde9f67c528794602a288a8025836094362736fa0c4440a257f195282892c27094652b6284027748bce201603835417b535f928a439279103a050c931406587f38a1524d02dcc6a5888775ee04482a82ea0507b").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840348", 16).unwrap(),
        gas_limit: u64::from_str_radix("8477a0d", 16).unwrap(),
        gas_used: u64::from_str_radix("16abfac", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd28", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5f933d2223a16c35117784df4e991fb364e63e5af05c259b8a3bc61285f60c5e358fc50994a039ec72e3881cdee16317e639c91cc30183c0ec50cadeff7eec90d00").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch9() -> ETHHeader {
    // "hash": "0x2a169c8232065e72f15747b128cd8d27458774f4f06deb1b17538adb12f627c7",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840349&boolean=false&apikey=<>
    //https://bscscan.com/block/25428809
    fix(ETHHeader {
        parent_hash: hex!("678572fa9b9f6a982072a6f861735da54fd6a538d20faccc013ce129512eca31").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("cc8e6d00c17eb431350c6c50d8b8f05176b90b11").into(),
        root: hex!("fe14fb52957fb4f7e01469daa7fe9e30cfc0248bc288ae600b3801b62474bad9"),
        tx_hash: hex!("5bad2f66dcf3dd960799d79a1d35099a7df9787d9304f29c74da118b52e0519e").into(),
        receipt_hash: hex!("db19db23a6a1a8d6f0a656b06815591dd752b1b344278099e74fa32056d93c2c").into(),
        bloom: hex!("4e308a000048201d4e0d21e481600306a21e0874045cc428623205eb50811900f2208848a12a10204b32153a1104872843530c34568803824304400298743203a42006702805042001724e080389d0fa2839e03a12450090e90614e8802fbd0d04a1142e0e760201a46620b00194cc43ee508053b58e1e014463001110550c6bd08830013eade48418c8c3882801a52040369c439900540c340d92501c448aac22a83801257a5942a8067c58c62f9c102488002c4ac6b54022453c2b6972844e6508084a0408154214856a3d8840120061086e00558c6a14254d913e5b07ee280b3263a54e6020027b61a280a4000108d1a3242c411024eaa1820c2a2c9ca054").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840349", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f3294", 16).unwrap(),
        gas_used: u64::from_str_radix("8c5ea4", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd2b", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5d543277ef6dff210804e9dadb8dfd0d74ad17a6ce4b2519f57a8b2467bf8836a61b0b7649ddce2bf3c1ef2dea4bb9fbefaab06cfc890a0ae87f1daea8547bcaf01").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch10() -> ETHHeader {
    // "hash": "0xb2f063bbf649d53b4213716b0e58c0a466088ce5f433d58ac1c978197d7d0481",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184034a&boolean=false&apikey=<>
    //https://bscscan.com/block/25428810
    fix(ETHHeader {
        parent_hash: hex!("2a169c8232065e72f15747b128cd8d27458774f4f06deb1b17538adb12f627c7").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("d1d6bf74282782b0b3eb1413c901d6ecf02e8e28").into(),
        root: hex!("9e65ec2b125bd730bdcae21edf6488c96ae965178ed18bc317242d8126d64e14"),
        tx_hash: hex!("b963ac95d92efd167d6563a08c72c6abc60f2bfb3fa90e1c4d0ba7c2f6cbb487").into(),
        receipt_hash: hex!("e976c7e6284aa0b61a9f39df8cb322de0df9c06ff4e14a57cec98fb1679cccf1").into(),
        bloom: hex!("5f35db6caeefbd3aee2a7f5fe3fe2b6cf99a6e7fce77becd6bd32a9eaafb33d07be29bd55ff6f6dfbbb53b78de6eaf3d3343792294fe15c7f9bafa9d8feeaff3366c486b1d9fce455db7a37f0aae75fbe775f43b89f6be97fbdc3545afe7dba36dd7743c56879ef14a57e3a7ae9448f17ae07173cd4acdc5553b8ad1f6a58ca8dad5b7377e89b7f077ec57b79e7a36f07c3dcca7357e576d65b7c6e1ffe67effbf072d6bbacddb1e343f39ffaf4b254905eb171f75012f775ef7fd4b21cbd77fa5485d1f7d890faef89bf0e13acb7c457161ee54dd2bb6978c19d7effb9aef659f7187c2357f5ee337d9b40fa52b79cdebae6dca732fad6acfaf45b4a5827ddf").into(),
        difficulty: 2,
        number: u64::from_str_radix("184034a", 16).unwrap(),
        gas_limit: u64::from_str_radix("836f363", 16).unwrap(),
        gas_used: u64::from_str_radix("19ce982", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd2e", 16).unwrap(),
        extra_data: hex!("d883010112846765746888676f312e31392e32856c696e75780000005b7663b526a6eb4032b8df817c67acec771ac72d9cfa292f95f70c784d4c0ba72a54b5330754d990af9f642c389c2c91ef789d179d18d247f96ca5e6f7abea76d0fb8faa01").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch11() -> ETHHeader {
    // "hash": "0xb2f063bbf649d53b4213716b0e58c0a466088ce5f433d58ac1c978197d7d0481",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184034b&boolean=false&apikey=<>
    //https://bscscan.com/block/25428811
    fix(ETHHeader {
        parent_hash: hex!("b2f063bbf649d53b4213716b0e58c0a466088ce5f433d58ac1c978197d7d0481").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("e2d3a739effcd3a99387d015e260eefac72ebea1").into(),
        root: hex!("e0e940aa14b0227025c04ab4fcd9d697be070e436629988ed22f3dfb48c2a32f"),
        tx_hash: hex!("4f812459d124264098289669f1e28c66b67b3981c88935f9f9259c39f9f7fa29").into(),
        receipt_hash: hex!("cced4e5a733b42d390712dcf3d21389cafeba091e1ffa478d5cecf3a6bebb18a").into(),
        bloom: hex!("8639eb2dad6335137aad30c7a0b4c82e349b08e85d3afd6e67cf0be2a1e41372d4e21e3e96e37d34d799bbf49008b7756909aa519a6e11abf71cd49affee62424a34f6e309077c335193414f02e171bf689b0a7d47f5d8ade0cef657ea2f9fb95fc658b13a87d310c073a4d765919b6b6ad47943f7fd2dcc6ca04d982aea8fdb30be6767bb99df89dcfd06481a10924692379cdfbbe69d4e2ffb9aedfdffdebfc2fbbb1b50cce145c73ae2e98fed5c7575ad2a76a1fd0be50e085734e9504951e3298d4a0c0b598255ffcce3889e73a1b8fffd5671bb697d65fb530ef654e0bb37bbdeb307a05027ffcd9f07954c9e57cd4ecf4a6747ecdce69b2b2daf3ed4f9").into(),
        difficulty: 1,
        number: u64::from_str_radix("184034b", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f2a55", 16).unwrap(),
        gas_used: u64::from_str_radix("1266fd1", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd32", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b5f513495360e6cbc4a21dc50f4ec4072244c2a0729219c26b0ae12c0d892d531f79726208190a8baae57735a811be462508dd76035a4e3036be0b30769be63de400").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_non_epoch_block_after_epoch12() -> ETHHeader {
    // "hash": "0x96100b959f23064477efb2640bf1563ce9f5d81140c3102a936abec64eaf7d14",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x184034c&boolean=false&apikey=<>
    //https://bscscan.com/block/25428812
    fix(ETHHeader {
        parent_hash: hex!("41340004f2bf264a54089a723ad36f2b678762ead1463ab2ea97e59aa0cb7b60").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("733fda7714a05960b7536330be4dbb135bef0ed6").into(),
        root: hex!("a71b4ef487fa323098c2b61f4bf10bdeaeea1f5ce8abca4a8b588f5b3cc5e864"),
        tx_hash: hex!("5088e98dcd16b79b9af8a6362a3c82b1878e97012d386c5b21c85e5f14360467").into(),
        receipt_hash: hex!("261a0747604fdde53c695bdff7788243ca8e42fd086b942cd15e65878ed2109e").into(),
        bloom: hex!("726e9faee179fe78ffbfbb7cf38e2bffe6ddbe71ca5bd7f2b97ffbfb3f87f976ffa7c56c3efbf93b77f3337569f6614d766d7f9125ad49afd6adedf794f7eafa62c8bec3ff77f7df75f0f9dabea87677bfbaeb69edf77ee9ba7f8e56af6dba62daa532337fae266d57dfff8d7f81fbc6df6cd4f7b5efb5fbcce3eaffbbdbffeaf5b9efb276ffbb25d9fd27eeafbdf5b065eff7a7b76c1fedf9fb8fe93ff9bf7a9677d837f8eff6d3b752adfa6f9efbcc7ffdbbf4f94debf3bf70ffe7bfde775e35b3be9aafef43fafcfb4de7d9dff257ebf77baa57dbf73dd77ffddfddbee274bc7f7f9bfd3c5febbdeafeb4effbcbc4da336dfd4fcded78fb4769d0be3f28fe").into(),
        difficulty: 1,
        number: u64::from_str_radix("184034c", 16).unwrap(),
        gas_limit: u64::from_str_radix("847697e", 16).unwrap(),
        gas_used: u64::from_str_radix("2d10773", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0cd36", 16).unwrap(),
        extra_data: hex!("d683010112846765746886676f312e3139856c696e757800000000005b7663b59aa5d7d9238a607caee3e7efe76817f69fb24ce9261a4306878fdebf91a258413c88d7381d7298dbbee24a0080183af9ab1730d5d41c773c99c63f8a8937876200").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

pub fn create_previous_epoch_block() -> ETHHeader {
    //"hash": "0x66eef8f9b1ed19064a56d366288e0ae2bbd1a265cdd9891d42171433b2a3f128",
    //https://api.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1840278&boolean=false&apikey=<>
    //https://bscscan.com/block/25428600
    fix(ETHHeader {
        parent_hash: hex!("29c8cd4c35bdca4fc29d1821ef936700bdd304be29fe137163978810081ea7ea").into(),
        uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
        coinbase: hex!("cc8e6d00c17eb431350c6c50d8b8f05176b90b11").into(),
        root: hex!("0d260c07d69e5b74ca30f8b0a3a2519e8c0af486c23b508ccfead58c09bcb1a7"),
        tx_hash: hex!("158ad7626ee06dfa7d83b3084937da89dbfc259da1834ec3fce57404a77e7c98").into(),
        receipt_hash: hex!("d559ac9320662feecbd4a2f6ada6c6e94f616b530ea5f3eb621be33698dbab42").into(),
        bloom: hex!("91309e11801c027000024026808805430888006c895805418195d117012c8a24240405c00842544a03a01990844802220282000404084084404500750cf404f012200c480009800007e12a0848804522ed18420000438012c204060e8e39aa8a118a52200e021401001520c80510a90208602801d80c1e0401b88198302625421888202806290c8040a8b2000634549200244441902002ec30148ae804856a3403008003b018186a604210e1020a9400912820042012050288082d0101934009210240020045c54e40410ca5c8003008200000021168241101414036d010ea20001c14100431444403400018040804104044108ac80c804000826b05900642c4").into(),
        difficulty: 2,
        number: u64::from_str_radix("1840278", 16).unwrap(),
        gas_limit: u64::from_str_radix("83f4315", 16).unwrap(),
        gas_used: u64::from_str_radix("4ac1b7", 16).unwrap(),
        timestamp: u64::from_str_radix("63e0caab", 16).unwrap(),
        extra_data: hex!("d983010112846765746889676f312e31372e3133856c696e757800005b7663b50bac492386862ad3df4b666bc096b0505bb694da295e26495cef6f69dfa69911d9d8e4f3bbadb89b2d4c407bbe49438ed859fe965b140dcf1aab71a93f349bbafec1551819b8be1efea2fc46ca749aa161dd481a114a2e761c554b641742c973867899d370f657164e5b75689b64b7fd1fa275f334f28e1872b61c6014342d914470ec7ac2975be345796c2b73564052d8e469ed0721c4e53379dc3c912289307ae2f5b9e386cd1b50a4550696d957cb4900f03a8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec739bb832254baf4e8b4cc26bd2b52b31389b56e98ba6f79b60359f141df90a0c745125b131caaffd12b4dd66d7c2c7e57f628210187192fb89d4b99dd4be807dddb074639cd9fa61b47676c064fc50d62ccc8e6d00c17eb431350c6c50d8b8f05176b90b11d1d6bf74282782b0b3eb1413c901d6ecf02e8e28e2d3a739effcd3a99387d015e260eefac72ebea1e9ae3261a475a27bb1028f140bc2a7c843318afdea0a6e3c511bbd10f4519ece37dc24887e11b55dee226379db83cffc681495730c11fdde79ba4c0cef0274e31810c9df02f98fafde0f841f4e66a1cd2d3fc2e33b02dc760228b4ea78e3b77a7c21b3895cabf3495e618f8c59597daa3c67f933f45d5c16813c0c874222271e5e25aa0d01dc94c1ead1f4c3dd28b0a500").into(),
        mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
        nonce: hex!("0000000000000000").into(),
        hash: [0; 32],
        is_epoch: false,
        new_validators: vec![],
    })
}

fn fix(src: ETHHeader) -> ETHHeader {
    let raw: RawETHHeader = src.try_into().unwrap();
    (&raw).try_into().unwrap()
}

fn to_rlp(proof: alloc::vec::Vec<alloc::vec::Vec<u8>>) -> BytesMut {
    let mut rlp = RlpStream::new_list(proof.len());
    for v in proof {
        rlp.append(&v);
    }
    rlp.out()
}
