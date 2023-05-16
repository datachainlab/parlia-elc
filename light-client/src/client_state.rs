use alloc::borrow::ToOwned as _;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::time::Duration;

use ibc::core::ics02_client::client_state::{
    downcast_client_state, ClientState as IBCClientState, UpdatedState,
};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState as IBCConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as IBCHeader;
use ibc::core::ics02_client::trust_threshold::TrustThreshold;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc::core::ics24_host::identifier::{ChainId as IBCChainId, ClientId};
use ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, ClientStatePath, CommitmentPath,
    ConnectionPath, ReceiptPath, SeqRecvPath,
};
use ibc::core::{ContextError, ValidationContext};
use ibc::Height;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use ibc_proto::protobuf::Protobuf;
use patricia_merkle_trie::keccak::keccak_256;
use patricia_merkle_trie::{keccak, EIP1186Layout};
use prost::Message as _;
use rlp::Rlp;
use trie_eip1186::VerifyError;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};

use crate::consensus_state::ConsensusState;
use crate::errors::{into_client_error, Error};
use crate::header::Header;
use crate::misc::{
    new_ibc_height, new_ibc_height_with_chain_id, Account, Address, ChainId, Hash, NanoTime,
    ValidatorReader, Validators,
};
use crate::path::Path;

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Address,
    pub latest_height: Height,
    pub trust_level: TrustThreshold,
    pub trusting_period: NanoTime,
    pub frozen: bool,
}

impl ClientState {
    pub fn client_type() -> ClientType {
        //TODO fix name
        ClientType::new("99-parlia".to_owned())
    }

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
}

impl IBCClientState for ClientState {
    fn chain_id(&self) -> IBCChainId {
        self.chain_id.id().to_string().into()
    }

    fn client_type(&self) -> ClientType {
        Self::client_type()
    }

    fn latest_height(&self) -> Height {
        self.latest_height.to_owned()
    }

    fn is_frozen(&self) -> bool {
        self.frozen
    }

    fn frozen_height(&self) -> Option<Height> {
        None
    }

    fn expired(&self, _elapsed: Duration) -> bool {
        todo!("move from assert_within_trusted_period")
    }

    fn zero_custom_fields(&mut self) {
        todo!()
    }

    fn initialise(
        &self,
        _consensus_state: Any,
    ) -> Result<Box<dyn IBCConsensusState<Error = ClientError>>, ClientError> {
        todo!()
    }

    fn check_header_and_update_state(
        &self,
        ctx: &dyn ValidationContext,
        client_id: ClientId,
        header: Any,
    ) -> Result<UpdatedState, ClientError> {
        let header: Header = header.try_into()?;

        let trusted_client_cons_state_path =
            ClientConsensusStatePath::new(&client_id, &header.trusted_height());
        let trusted_consensus_state: ConsensusState = ctx
            .consensus_state(&trusted_client_cons_state_path)
            .map_err(into_client_error)?
            .as_ref()
            .try_into()?;

        // Ensure last consensus state is within the trusting period
        let now = ctx.host_timestamp().map_err(into_client_error)?;
        trusted_consensus_state.assert_within_trust_period(now, self.trusting_period)?;
        trusted_consensus_state
            .assert_within_trust_period(header.timestamp(), self.trusting_period)?;

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
        let new_consensus_state = ConsensusState {
            state_root: account.storage_root.into(),
            timestamp: header.timestamp(),
            validator_set: header.validator_set().clone(),
        };

        Ok(UpdatedState {
            client_state: Box::new(new_client_state),
            consensus_state: Box::new(new_consensus_state),
        })
    }

    fn check_misbehaviour_and_update_state(
        &self,
        _ctx: &dyn ValidationContext,
        _client_id: ClientId,
        _misbehaviour: Any,
    ) -> Result<Box<dyn IBCClientState<Error = ClientError>>, ContextError> {
        todo!()
    }

    fn verify_upgrade_client(
        &self,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
        _proof_upgrade_client: MerkleProof,
        _proof_upgrade_consensus_state: MerkleProof,
        _root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn update_state_with_upgrade_client(
        &self,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
    ) -> Result<UpdatedState, ClientError> {
        todo!()
    }

    fn verify_client_consensus_state(
        &self,
        _proof_height: ibc::Height,
        _counterparty_prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _client_cons_state_path: &ClientConsensusStatePath,
        _expected_consensus_state: &dyn IBCConsensusState<Error = ClientError>,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_connection_state(
        &self,
        _proof_height: ibc::Height,
        _counterparty_prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _counterparty_conn_path: &ConnectionPath,
        _expected_counterparty_connection_end: &ConnectionEnd,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_channel_state(
        &self,
        _proof_height: ibc::Height,
        _counterparty_prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _counterparty_chan_end_path: &ChannelEndPath,
        _expected_counterparty_channel_end: &ChannelEnd,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_client_full_state(
        &self,
        _proof_height: ibc::Height,
        _counterparty_prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _client_state_path: &ClientStatePath,
        _expected_client_state: Any,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_packet_data(
        &self,
        _ctx: &dyn ValidationContext,
        _height: ibc::Height,
        _connection_end: &ConnectionEnd,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _commitment_path: &CommitmentPath,
        _commitment: PacketCommitment,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_packet_acknowledgement(
        &self,
        _ctx: &dyn ValidationContext,
        _height: ibc::Height,
        _connection_end: &ConnectionEnd,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _ack_path: &AckPath,
        _ack: AcknowledgementCommitment,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_next_sequence_recv(
        &self,
        _ctx: &dyn ValidationContext,
        _height: ibc::Height,
        _connection_end: &ConnectionEnd,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _seq_recv_path: &SeqRecvPath,
        _sequence: Sequence,
    ) -> Result<(), ClientError> {
        todo!()
    }

    fn verify_packet_receipt_absence(
        &self,
        _ctx: &dyn ValidationContext,
        _height: ibc::Height,
        _connection_end: &ConnectionEnd,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _receipt_path: &ReceiptPath,
    ) -> Result<(), ClientError> {
        todo!()
    }
}

impl Protobuf<RawClientState> for ClientState {}
impl Protobuf<Any> for ClientState {}

impl TryFrom<RawClientState> for ClientState {
    type Error = ClientError;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let chain_id = ChainId::new(value.chain_id);

        let latest_height =
            new_ibc_height_with_chain_id(&chain_id, raw_latest_height.revision_height)?;

        let raw_ibc_store_address = value.ibc_store_address.clone();
        let ibc_store_address = raw_ibc_store_address
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_store_address))?;

        let trust_level = {
            let trust_level: Fraction = value.trust_level.ok_or(Error::MissingTrustLevel)?;
            let trust_level = TrustThreshold::new(trust_level.numerator, trust_level.denominator)?;
            // see https://github.com/tendermint/tendermint/blob/main/light/verifier.go#L197
            let numerator = trust_level.numerator();
            let denominator = trust_level.denominator();
            if numerator * 3 < denominator || numerator > denominator || denominator == 0 {
                return Err(ClientError::InvalidTrustThreshold {
                    numerator,
                    denominator,
                });
            }
            trust_level
        };

        let trusting_period = value.trusting_period;
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
            trust_level: Some(Fraction {
                numerator: value.trust_level.numerator(),
                denominator: value.trust_level.denominator(),
            }),
            trusting_period: value.trusting_period.to_owned(),
            frozen: value.frozen.to_owned(),
        }
    }
}

impl TryFrom<&dyn IBCClientState<Error = ClientError>> for ClientState {
    type Error = ClientError;

    fn try_from(value: &dyn IBCClientState<Error = ClientError>) -> Result<Self, Self::Error> {
        downcast_client_state::<Self>(value)
            .ok_or_else(|| ClientError::ClientArgsTypeMismatch {
                client_type: ClientState::client_type(),
            })
            .map(Clone::clone)
    }
}

impl TryFrom<Any> for ClientState {
    type Error = ClientError;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CLIENT_STATE_TYPE_URL {
            return Err(ClientError::UnknownClientStateType {
                client_state_type: any.type_url,
            });
        }
        RawClientState::decode(any.value.as_slice())
            .map_err(ClientError::Decode)?
            .try_into()
    }
}

impl From<ClientState> for Any {
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

struct DefaultValidatorReader<'a> {
    ctx: &'a dyn ValidationContext,
    client_id: &'a ClientId,
}

impl<'a> DefaultValidatorReader<'a> {
    fn new(ctx: &'a dyn ValidationContext, client_id: &'a ClientId) -> Self {
        Self { ctx, client_id }
    }
}

impl<'a> ValidatorReader for DefaultValidatorReader<'a> {
    fn read(&self, ibc_height: ibc::Height) -> Result<Validators, Error> {
        let height = new_ibc_height(ibc_height.revision_number(), ibc_height.revision_height())?;
        let client_cons_state_path = ClientConsensusStatePath::new(self.client_id, &height);
        let consensus_state: ConsensusState = self
            .ctx
            .consensus_state(&client_cons_state_path)
            .map_err(Error::ContextError)?
            .as_ref()
            .try_into()
            .map_err(Error::ICS02Error)?;
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