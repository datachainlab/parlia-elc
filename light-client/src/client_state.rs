use crate::errors::Error;
use alloc::borrow::ToOwned as _;
use alloc::string::ToString;
use alloc::vec::Vec;
use ibc::core::ics02_client::client_state::{self, AnyClientState};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::error::Error as ICS02Error;
use ibc::core::ics02_client::trust_threshold::TrustThreshold;

use crate::misc::{new_ibc_height_with_chain_id, ChainId, NanoTime};
use ibc_proto::google::protobuf::Any;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::{ClientState as RawClientState, Fraction};
use prost::Message as _;

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub ibc_store_address: Vec<u8>,
    pub latest_height: ibc::Height,
    pub trust_level: TrustThreshold,
    pub trusting_period: NanoTime,
    pub frozen: bool,
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let chain_id = ChainId::new(value.chain_id);

        let latest_height =
            new_ibc_height_with_chain_id(&chain_id, raw_latest_height.revision_height)?;

        let ibc_store_address = value.ibc_store_address;

        let trust_level = {
            let trust_level: Fraction = value.trust_level.ok_or(Error::MissingTrustLevel)?;
            let trust_level = TrustThreshold::new(trust_level.numerator, trust_level.denominator)
                .map_err(Error::ICS02Error)?;
            // see https://github.com/tendermint/tendermint/blob/main/light/verifier.go#L197
            let numerator = trust_level.numerator();
            let denominator = trust_level.denominator();
            if numerator * 3 < denominator || numerator > denominator || denominator == 0 {
                return Err(Error::ICS02Error(ICS02Error::invalid_trust_threshold(
                    numerator,
                    denominator,
                )));
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
            ibc_store_address: value.ibc_store_address,
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

impl client_state::ClientState for ClientState {
    type UpgradeOptions = ();

    fn chain_id(&self) -> ibc::core::ics24_host::identifier::ChainId {
        ibc::core::ics24_host::identifier::ChainId::from(self.chain_id.id().to_string())
    }

    fn client_type(&self) -> ClientType {
        todo!()
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

    fn upgrade(
        self,
        _upgrade_height: ibc::Height,
        _upgrade_options: Self::UpgradeOptions,
        _chain_id: ibc::core::ics24_host::identifier::ChainId,
    ) -> Self {
        todo!();
    }

    fn wrap_any(self) -> AnyClientState {
        todo!();
    }
}

impl TryFrom<Any> for ClientState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CLIENT_STATE_TYPE_URL {
            return Err(Error::UnexpectedTypeUrl(any.type_url));
        }
        RawClientState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl TryFrom<ClientState> for Any {
    type Error = Error;

    fn try_from(value: ClientState) -> Result<Self, Error> {
        let value: RawClientState = value.into();
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: PARLIA_CLIENT_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}
