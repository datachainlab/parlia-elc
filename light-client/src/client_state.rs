use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use core::time::Duration;

use lcp_types::{Any, ClientId, Height};
use light_client::HostClientReader;
use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use patricia_merkle_trie::keccak::keccak_256;
use patricia_merkle_trie::{keccak, EIP1186Layout};
use prost::Message as _;
use rlp::Rlp;
use trie_eip1186::{verify_proof as native_verifyProof, VerifyError};


use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};

use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::misc::{new_height, Account, Address, ChainId, Hash, ValidatorReader, Validators, decode_proof};
use crate::path::Path;

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Address,
    pub latest_height: Height,
    pub trust_level: Fraction,
    pub trusting_period: Duration,
    pub frozen: bool,
}

impl ClientState {
    pub fn verify_commitment(
        storage_root: &Hash,
        storage_proof_rlp: &[u8],
        path: impl Path,
        expected_value: &Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let storage_proof = decode_proof(storage_proof_rlp)?;
        verify_proof(
            storage_root,
            &storage_proof,
            path.storage_key(),
            expected_value,
        )
    }

    pub fn check_header_and_update_state(
        &self,
        ctx: &dyn HostClientReader,
        trusted_consensus_state: &ConsensusState,
        client_id: ClientId,
        header: Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        // Ensure last consensus state is within the trusting period
        let now = ctx.host_timestamp();
        trusted_consensus_state.assert_not_expired(now, self.trusting_period)?;
        trusted_consensus_state.assert_not_expired(header.timestamp()?, self.trusting_period)?;

        // Ensure header revision is same as chain revision
        let header_height = header.height();
        if header_height.revision_number() != self.chain_id.version() {
            return Err(Error::UnexpectedHeaderRevision(
                self.chain_id.version(),
                header_height.revision_number(),
            ));
        }

        // Ensure header is valid
        header.verify(DefaultValidatorReader::new(ctx, &client_id), &self.chain_id)?;

        let mut new_client_state = self.clone();
        new_client_state.latest_height = header.height();

        // Ensure world state is valid
        let account = resolve_account(
            header.state_root(),
            &header.account_proof()?,
            &new_client_state.ibc_store_address,
        )?;

        let new_consensus_state = ConsensusState {
            state_root: account
                .storage_root
                .try_into()
                .map_err(Error::UnexpectedStorageRoot)?,
            timestamp: header.timestamp()?,
            validator_set: header.validator_set().clone(),
        };

        Ok((new_client_state, new_consensus_state))
    }
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let chain_id = ChainId::new(value.chain_id);

        let latest_height = new_height(
            raw_latest_height.revision_number,
            raw_latest_height.revision_height,
        );

        let raw_ibc_store_address = value.ibc_store_address.clone();
        let ibc_store_address = raw_ibc_store_address
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_store_address))?;

        let trust_level = {
            let trust_level: Fraction = value.trust_level.ok_or(Error::MissingTrustLevel)?;
            // see https://github.com/tendermint/tendermint/blob/main/light/verifier.go#L197
            let numerator = trust_level.numerator;
            let denominator = trust_level.denominator;
            if numerator * 3 < denominator || numerator > denominator || denominator == 0 {
                return Err(Error::InvalidTrustThreshold(numerator, denominator));
            }
            trust_level
        };

        let trusting_period = Duration::from_secs(value.trusting_period);
        let frozen = value.frozen;

        Ok(Self {
            chain_id,
            ibc_store_address,
            latest_height,
            trust_level,
            trusting_period,
            frozen,
        })
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.id(),
            ibc_store_address: value.ibc_store_address.to_vec(),
            latest_height: Some(parlia_ibc_proto::ibc::core::client::v1::Height {
                revision_number: value.latest_height.revision_number(),
                revision_height: value.latest_height.revision_height(),
            }),
            trust_level: Some(value.trust_level),
            trusting_period: value.trusting_period.as_secs(),
            frozen: value.frozen.to_owned(),
        }
    }
}

impl TryFrom<IBCAny> for ClientState {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CLIENT_STATE_TYPE_URL {
            return Err(Error::UnknownClientStateType(any.type_url));
        }
        RawClientState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl From<ClientState> for IBCAny {
    fn from(value: ClientState) -> Self {
        let value: RawClientState = value.into();
        let mut v = Vec::new();
        value
            .encode(&mut v)
            .expect("encoding to `Any` from `ParliaClientState`");
        Self {
            type_url: PARLIA_CLIENT_STATE_TYPE_URL.to_owned(),
            value: v,
        }
    }
}

impl From<ClientState> for Any {
    fn from(value: ClientState) -> Self {
        IBCAny::from(value).into()
    }
}

impl TryFrom<Any> for ClientState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

struct DefaultValidatorReader<'a> {
    ctx: &'a dyn HostClientReader,
    client_id: &'a ClientId,
}

impl<'a> DefaultValidatorReader<'a> {
    fn new(ctx: &'a dyn HostClientReader, client_id: &'a ClientId) -> Self {
        Self { ctx, client_id }
    }
}

impl<'a> ValidatorReader for DefaultValidatorReader<'a> {
    fn read(&self, height: Height) -> Result<Validators, Error> {
        let any = self
            .ctx
            .consensus_state(self.client_id, &height)
            .map_err(Error::LCPError)?;
        let consensus_state = ConsensusState::try_from(any)?;
        Ok(consensus_state.validator_set)
    }
}

fn resolve_account(
    state_root: &Hash,
    account_proof: &[Vec<u8>],
    address: &Address,
) -> Result<Account, Error> {
    match verify_proof(state_root, account_proof, address, &None) {
        Ok(_) => Err(Error::AccountNotFound(*address)),
        Err(Error::UnexpectedStateExistingValue(value, _)) => Rlp::new(&value).try_into(),
        Err(err) => Err(err),
    }
}

fn verify_proof(
    root: &Hash,
    proof: &[Vec<u8>],
    key: &[u8],
    expected_value: &Option<Vec<u8>>,
) -> Result<(), Error> {
    let expected_value = expected_value.as_ref().map(|e| rlp::encode(e).to_vec());
    trie_eip1186::verify_proof::<EIP1186Layout<keccak::KeccakHasher>>(
        &root.into(),
        proof,
        &keccak_256(key),
        expected_value.as_deref(),
    )
    .map_err(|err| match err {
        VerifyError::ExistingValue(value) => {
            Error::UnexpectedStateExistingValue(value, key.to_vec())
        }
        VerifyError::NonExistingValue(_) => Error::UnexpectedStateNonExistingValue(key.to_vec()),
        VerifyError::DecodeError(_) => Error::UnexpectedStateDecodeError(key.to_vec()),
        VerifyError::HashDecodeError(_) => Error::UnexpectedStateHashDecodeError(key.to_vec()),
        VerifyError::HashMismatch(_) => Error::UnexpectedStateHashMismatch(key.to_vec()),
        VerifyError::ValueMismatch(_) => Error::UnexpectedStateValueMismatch(key.to_vec()),
        VerifyError::IncompleteProof => Error::UnexpectedStateIncompleteProof(key.to_vec()),
    })
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use rlp::Rlp;
    use alloc::borrow::ToOwned as _;
    use patricia_merkle_trie::{EIP1186Layout, keccak};
    use patricia_merkle_trie::keccak::keccak_256;
    use prost::bytes::{BufMut, BytesMut};

    use crate::client_state::{resolve_account, verify_proof, ClientState};
    use crate::misc::{Account, Hash};
    use crate::path::{Path, YuiIBCPath};
    use trie_eip1186::{verify_proof as native_verifyProof, VerifyError};

    #[test]
    fn test_resolve_account() {
        let address = hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef");
        let state_root: Hash =
            hex!("c7095cc31e155302a3ff06970f0df0efa1abf5fe6e4be6cc450cc5f9421c2c9f");
        let account_proof = vec![
            hex!("f873a12023b3309d10ca81366908080d27b9f3a46293a38eb039f35393e1af81413e70c8b84ff84d0489020000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec(),
        ];
        let account = Account {
            storage_root: hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                .to_vec(),
        };
        let v = resolve_account(&state_root, &account_proof, &address);
        match v {
            Ok(actual) => assert_eq!(actual, account),
            Err(e) => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_verify_proof() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let storage_root = hex!("c5bbc7e086abad66f3d4b49cc39c27e4864834ce3d21d91692c513481bf9de1b");
        let storage_proof = vec![
            hex!("f8518080a051c7191217d318e27eed8b8f0b2c81df8ad258037ecdb3ee8808ab982623adba8080808080808080a028e886a776e1a5ccaf6819bc26ae7f83616639014e9751eb8d68eaaac54966448080808080").to_vec(),
            hex!("f7a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594ebed59a7f647152af99ef0fd8e3f7e81bd7b1fd7").to_vec(),
        ];
        let expected = hex!("ebed59a7f647152af99ef0fd8e3f7e81bd7b1fd7").to_vec();
        if let Err(e) = verify_proof(&storage_root, &storage_proof, &key, &Some(expected)) {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_verify_commitment() {
        let storage_root = hex!("2a76cf6e2521e6a413a912d96a4220479c68283130d6cef6966f4ff1cf437a32");
        let storage_proof = vec![
            hex!("f8918080a0f0d0b833ffb94d6962b74e4b1d5bc5a7cceca74616832065750c00ddd9d1b329808080a0044f9d4608bdd7ff7943cee62a73ac4daeff3c495907afd494dce25436b0c534a0dd774c97b7b9a5ff4ba0073aa76d58729ece6e20211ed97ef56b8baea52df39480808080a0b19b826b59a7db662e9af57a595710163588c476f642b97df805705790dee4e680808080").to_vec(),
            hex!("f843a030ce6503f917cf7d4ecf54b344bf12226dc86adea09aeb7829c0bb8a1eae2c1aa1a03334000000000000000000000000000000000000000000000000000000000000").to_vec(),
        ];
        let p = Rlp::new(&storage_proof[0]);
        let pp : alloc::vec::Vec<u8> = p.as_val().unwrap();
        let path = YuiIBCPath::from("clients/client1/clientState".as_bytes());
        let mut expected = [0_u8; 32];
        expected[0] = 51;
        expected[1] = 52;
        if let Err(e) = ClientState::verify_commitment(
            &storage_root,
            pp.as_slice(),
            path,
            &Some(expected.to_vec()),
        ) {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_try_from_any() {
        // This is ibc-parlia-relay's unit test data
        let relayer_client_state_protobuf = vec![
            10, 39, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115,
            46, 112, 97, 114, 108, 105, 97, 46, 118, 49, 46, 67, 108, 105, 101, 110, 116, 83, 116,
            97, 116, 101, 18, 38, 8, 143, 78, 18, 20, 170, 67, 211, 55, 20, 94, 137, 48, 208, 28,
            180, 230, 10, 191, 101, 149, 198, 146, 146, 30, 26, 3, 16, 200, 1, 34, 4, 8, 1, 16, 3,
            40, 100,
        ];
        let any: lcp_types::Any = relayer_client_state_protobuf.try_into().unwrap();
        let cs: ClientState = any.try_into().unwrap();

        // Check if the result are same as relayer's one
        assert_eq!(0, cs.latest_height.revision_number());
        assert_eq!(200, cs.latest_height.revision_height());
        assert_eq!(9999, cs.chain_id.id());
        assert_eq!(0, cs.chain_id.version());
        assert_eq!(100, cs.trusting_period.as_secs());
        assert_eq!(1, cs.trust_level.numerator);
        assert_eq!(3, cs.trust_level.denominator);
        assert_eq!(
            hex!("aa43d337145e8930d01cb4e60abf6595c692921e"),
            cs.ibc_store_address
        );
    }

    #[test]
    fn test_verify_membership_with_connection_state() {
        use ibc_proto::ibc::core::commitment::v1::MerklePrefix;
        use ibc_proto::ibc::core::connection::v1::{ConnectionEnd, Counterparty, State, Version};

        use prost::Message;

        let storage_root = hex!("f4d65dd2af86e63e5288f0e2ebc1f5c2da9b401d2648afb49fb74b572a968d1a");
        let path = b"connections/connection-0".to_vec();
        let value_proof_list = vec![
            hex!("f901f1a0e82d1005abda0dbaa0902c43770d9dc398c50702086f00ab9df7447c79b678a7a084e18566da24bc07e7be1799899403811edee930436fd3adc5b9c2d285761272a08c41aafb59d00e2065923ac91614ff09ffe216e14bfae531b6be84ac200df42da0126fdcc6fd261e65d23367b45ab14ea9aa9fc9924b1458b101465177663db446a0ece30930b0eb4e30b247256232eb964a1745214d25ad24afd9abe9241bf68dcfa08259f9606fa6d93393d2df42dad317e9ff72fa2a9b5e96b1ef912fd70f1f07f2a0c79a2f5a8170e1588068124a9eba736432c9356eea666b85c1393eb3adfef05fa0852ba9427cbda9328449ba7f44626659ec18ae3d8e3679dddd7665ae14b1ba1fa0dd1e9df94d0deb3dd91184a99371924f03ddd82b9568c5ce8e4590f6c9d84773a0f8f6e4d72660d1857f3be96d1c9338c8a743931631b6ae989a722e0f1b6b6ad2a00919a868f3c8afc01f89729a4e3cd05948e013d6389656e0f8ba546ded16e77da00a0ce3e857333daabbdd1ce9f2f20309960071a573fbebe973a8f2ef25e69f34a016c799afd57d9644df5df08856b1205e17053921304e37449d3bec13a60aac73a0cc9b3cae2233573dbd970d71ccde6c060cdc063d2eee0add4f43f1770d0e4811a061cea851681bc1839f1462e634a53a66894a9fad9cb926d774cfcbd3ed9ef7bb8080").to_vec(),
            hex!("f8b180a07dbc8337ea92eb56afc5caeed7c6732654a154a2fa1498a0e49faf986323af42808080a060e1914b573ffcc64525ec9dd09a0a309f43a34b23e3e86b0663bf8b004d5f1180a04086ff29349bd47f5fd994973d0547d9c6f7438b65ad6497144bc3ab22ce5b408080a09b5d804d5d9f3b8e97e7305a2355eb8ea200212ed70bf3235ba0630d2d1ab2338080a0f4b194d8748d1c2191c783e25cb1c86f0cf91a9c6f4423ecc733afc406e5a586808080").to_vec(),
            hex!("f843a0203fc42ddf6c1b5bb218ce24e14c40af9e0eb127a5d76050d37d7369e2fc4a47a1a0ee0a0d14f90336be8485b9c018f7894507e574bc09f19bfc6c7f938ba98a2b1d").to_vec()
        ];

        let connection_end = ConnectionEnd {
            client_id: "mock-client-0".to_owned(),
            versions: vec![Version {
                identifier: "1".to_owned(),
                features: vec!["ORDER_ORDERED".to_owned(), "ORDER_UNORDERED".to_owned()],
            }],
            state: 3,
            counterparty: Some(Counterparty {
                client_id: "mock-client-1".to_owned(),
                connection_id: "connection-1".to_owned(),
                prefix: Some(MerklePrefix {
                    key_prefix: hex!("696263").to_vec(),
                }),
            }),
            delay_period: 3_000_000_000_u64,
        };

        let mut buf = alloc::vec::Vec::<u8>::new();
        connection_end.encode(&mut buf).unwrap();
        let expected_value = keccak_256(&buf).to_vec();
        let data: alloc::vec::Vec<u8> =
            hex!("ee0a0d14f90336be8485b9c018f7894507e574bc09f19bfc6c7f938ba98a2b1d").to_vec(); // from eth_getProof.
        assert_eq!(expected_value, data);
     //   let expected_value = Some(rlp::encode(&expected_value).to_vec());

        /*
        let path = keccak_256(&path).to_vec();
        let mut buffer = BytesMut::with_capacity(256);
        buffer.put(&path[..]);
        let storage_slot = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        buffer.put(&storage_slot[..]);
        let key: [u8; 32] = keccak_256(&buffer);
         */
        let path = YuiIBCPath::from(path.as_slice());
        let key = path.storage_key();

        assert!(verify_proof(&storage_root, &value_proof_list, key, &Some(expected_value)).is_ok());
    }

}
