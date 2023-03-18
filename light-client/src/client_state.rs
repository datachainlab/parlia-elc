use alloc::borrow::ToOwned as _;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::time::Duration;
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use ibc_proto::protobuf::Protobuf;
use lcp_types::{Any, ClientId, Height};
use light_client::HostClientReader;
use parlia_ibc_proto::google;
use patricia_merkle_trie::keccak::keccak_256;
use patricia_merkle_trie::{keccak, EIP1186Layout};
use prost::Message as _;
use rlp::Rlp;
use trie_eip1186::VerifyError;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};

use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::misc::{new_height, Account, Address, ChainId, Hash, ValidatorReader, Validators};
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
        let storage_proof = Rlp::new(storage_proof_rlp);
        let storage_proof = storage_proof.as_list().map_err(Error::RLPDecodeError)?;
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
        trusted_consensus_state.assert_within_trust_period(now, self.trusting_period.clone())?;
        trusted_consensus_state
            .assert_within_trust_period(header.timestamp()?, self.trusting_period.clone())?;

        // Ensure header revision is same as chain revision
        let header_height = header.height();
        if header_height.revision_number() != self.chain_id.version() {
            return Err(Error::UnexpectedHeaderRevision(
                self.chain_id.version(),
                header_height.revision_number(),
            )
            .into());
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

        let storage_size = account.storage_root.len();
        let new_consensus_state = ConsensusState {
            state_root: account
                .storage_root
                .try_into()
                .map_err(Error::UnexpectedStateRoot)?,
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

        let latest_height = new_height(chain_id.version(), raw_latest_height.revision_height);

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

        let trusting_period = value.trusting_period.ok_or(Error::MissingTrustingPeriod)?;
        let trusting_period =
            Duration::new(trusting_period.seconds as u64, trusting_period.nanos as u32);
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
            trusting_period: Some(google::protobuf::Duration {
                seconds: value.trusting_period.as_secs() as i64,
                nanos: value.trusting_period.subsec_nanos() as i32,
            }),
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
        let any = Any::from(
            self.ctx
                .consensus_state(self.client_id, &height)
                .map_err(Error::LCPError)?,
        );
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

    use crate::client_state::{resolve_account, verify_proof, ClientState};

    use crate::header::testdata::to_rlp;
    use crate::misc::{Account, Hash};
    use crate::path::YuiIBCPath;

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
        let storage_proof = to_rlp(vec![
            hex!("f8918080a0f0d0b833ffb94d6962b74e4b1d5bc5a7cceca74616832065750c00ddd9d1b329808080a0044f9d4608bdd7ff7943cee62a73ac4daeff3c495907afd494dce25436b0c534a0dd774c97b7b9a5ff4ba0073aa76d58729ece6e20211ed97ef56b8baea52df39480808080a0b19b826b59a7db662e9af57a595710163588c476f642b97df805705790dee4e680808080").to_vec(),
            hex!("f843a030ce6503f917cf7d4ecf54b344bf12226dc86adea09aeb7829c0bb8a1eae2c1aa1a03334000000000000000000000000000000000000000000000000000000000000").to_vec(),
        ]);

        let path = YuiIBCPath::from("clients/client1/clientState".as_bytes());

        let mut expected = [0_u8; 32];
        expected[0] = 51;
        expected[1] = 52;
        if let Err(e) = ClientState::verify_commitment(
            &storage_root,
            &storage_proof,
            path,
            &Some(expected.to_vec()),
        ) {
            unreachable!("{:?}", e);
        }
    }
}
