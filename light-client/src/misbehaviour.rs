use core::str::FromStr;

use light_client::types::{Any, ClientId};
use prost::Message;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Misbehaviour as RawMisbehaviour;

use crate::errors::Error;
use crate::header::Header;

pub const PARLIA_MISBEHAVIOUR_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Misbehaviour";

#[derive(Clone, Debug, PartialEq)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
}

impl TryFrom<RawMisbehaviour> for Misbehaviour {
    type Error = Error;

    fn try_from(value: RawMisbehaviour) -> Result<Self, Self::Error> {
        let client_id = ClientId::from_str(&value.client_id)
            .map_err(|_| Error::UnexpectedClientId(value.client_id))?;

        let header_1 = Header::try_from(value.header_1.ok_or(Error::MissingHeader1)?)?;
        let header_2 = Header::try_from(value.header_2.ok_or(Error::MissingHeader2)?)?;

        let h1_height = header_1.height();
        let h2_height = header_2.height();
        if h1_height != h2_height {
            return Err(Error::UnexpectedDifferentHeight(h1_height, h2_height));
        }
        if header_1.block_hash() == header_2.block_hash() {
            return Err(Error::UnexpectedSameBlockHash(h1_height));
        }
        Ok(Self {
            client_id,
            header_1,
            header_2,
        })
    }
}

impl TryFrom<IBCAny> for Misbehaviour {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Misbehaviour, Self::Error> {
        if any.type_url != PARLIA_MISBEHAVIOUR_TYPE_URL {
            return Err(Error::UnknownMisbehaviourType(any.type_url));
        }
        let raw = RawMisbehaviour::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl TryFrom<Any> for Misbehaviour {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}
