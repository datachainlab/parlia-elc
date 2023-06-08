use core::str::FromStr;

use lcp_types::{Any, ClientId};
use prost::Message;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Misbehaviour as RawMisbehavior;

use crate::errors::Error;
use crate::header::Header;

pub const PARLIA_MISBEHAVIOR_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Misbehavior";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Misbehavior {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
}

impl TryFrom<RawMisbehavior> for Misbehavior {
    type Error = Error;

    fn try_from(value: RawMisbehavior) -> Result<Self, Self::Error> {
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
            return Err(Error::UnexpectedSameBlockHash(h1_height, h2_height));
        }
        Ok(Self {
            client_id,
            header_1,
            header_2,
        })
    }
}

impl TryFrom<IBCAny> for Misbehavior {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Misbehavior, Self::Error> {
        if any.type_url != PARLIA_MISBEHAVIOR_TYPE_URL {
            return Err(Error::UnknownMisbehaviorType(any.type_url));
        }
        let raw = RawMisbehavior::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl TryFrom<Any> for Misbehavior {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}
