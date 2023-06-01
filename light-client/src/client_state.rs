use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use core::time::Duration;

use lcp_types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};

use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::misc::{new_height, Address, ChainId, Hash};

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    /// Chain parameters
    pub chain_id: ChainId,

    /// IBC Solidity parameters
    pub ibc_store_address: Address,
    pub ibc_commitments_slot: Hash,

    ///Light Client parameters
    pub trust_level: Fraction,
    pub trusting_period: Duration,

    /// State
    pub latest_height: Height,
    pub frozen: bool,
}

impl ClientState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: latest_height, frozen
    pub fn canonicalize(mut self) -> Self {
        self.latest_height = new_height(self.chain_id.version(), 0);
        self.frozen = false;
        self
    }

    pub fn check_header_and_update_state(
        &self,
        now: Time,
        trusted_consensus_state: &ConsensusState,
        header: Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        // Ensure last consensus state is within the trusting period
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
        header.verify(&self.chain_id)?;

        let mut new_client_state = self.clone();
        new_client_state.latest_height = header.height();

        let new_consensus_state = ConsensusState {
            state_root: header.storage_root(),
            timestamp: header.timestamp()?,
            validators_hash: header.new_validators_hash(),
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

        let raw_ibc_commitments_slot = value.ibc_commitments_slot.clone();
        let ibc_commitments_slot = raw_ibc_commitments_slot
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_commitments_slot))?;

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
            ibc_commitments_slot,
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
            ibc_commitments_slot: value.ibc_commitments_slot.to_vec(),
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

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use crate::client_state::ClientState;

    #[test]
    fn test_try_from_any() {
        let relayer_client_state_protobuf = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e7453746174651226088f4e1214aa43d337145e8930d01cb4e60abf6595c692921e1a0310c8012204080110032864").to_vec();
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
}
