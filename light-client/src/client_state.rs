use alloc::borrow::ToOwned as _;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::time::Duration;

use ibc::core::{ContextError, ValidationContext};
use ibc::core::ics02_client::client_state::{ClientState as IBCClientState, UpdatedState};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState as IBCConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::trust_threshold::TrustThreshold;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc::core::ics24_host::identifier::ClientId;
use ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, ClientStatePath, CommitmentPath,
    ConnectionPath, ReceiptPath, SeqRecvPath,
};
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use ibc_proto::protobuf::Protobuf;
use prost::Message as _;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};

use crate::errors::Error;
use crate::misc::{Address, ChainId, NanoTime, new_ibc_height_with_chain_id};

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Address,
    pub latest_height: ibc::Height,
    pub trust_level: TrustThreshold,
    pub trusting_period: NanoTime,
    pub frozen: bool,
}

impl ClientState {
    pub fn client_type() -> ClientType {
        //TODO fix name
        ClientType::new("99-parlia".to_owned())
    }
}

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

impl IBCClientState for ClientState {
    fn chain_id(&self) -> ibc::core::ics24_host::identifier::ChainId {
        ibc::core::ics24_host::identifier::ChainId::from(self.chain_id.id().to_string())
    }

    fn client_type(&self) -> ClientType {
        Self::client_type()
    }

    fn latest_height(&self) -> ibc::Height {
        self.latest_height.to_owned()
    }

    fn is_frozen(&self) -> bool {
        self.frozen
    }

    fn frozen_height(&self) -> Option<ibc::Height> {
        None
    }

    fn expired(&self, _elapsed: Duration) -> bool {
        todo!("move from assert_within_trusted_period")
    }

    fn zero_custom_fields(&mut self) {
        todo!()
    }

    fn initialise(&self, _consensus_state: Any) -> Result<Box<dyn IBCConsensusState>, ClientError> {
        todo!()
    }

    fn check_header_and_update_state(
        &self,
        _ctx: &dyn ValidationContext,
        _client_id: ClientId,
        _header: Any,
    ) -> Result<UpdatedState, ClientError> {
        todo!("move from client_def.rs")
    }

    fn check_misbehaviour_and_update_state(
        &self,
        _ctx: &dyn ValidationContext,
        _client_id: ClientId,
        _misbehaviour: Any,
    ) -> Result<Box<dyn IBCClientState>, ContextError> {
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
        _expected_consensus_state: &dyn IBCConsensusState,
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
