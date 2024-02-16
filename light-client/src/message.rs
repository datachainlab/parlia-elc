use crate::errors::Error;
use crate::header::{Header, PARLIA_HEADER_TYPE_URL};
use crate::misbehaviour::{Misbehaviour, PARLIA_MISBEHAVIOUR_TYPE_URL};
use light_client::types::Any;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ClientMessage {
    Header(Header),
    Misbehaviour(Misbehaviour),
}

impl TryFrom<Any> for ClientMessage {
    type Error = Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        match value.type_url.as_str() {
            PARLIA_HEADER_TYPE_URL => Ok(ClientMessage::Header(Header::try_from(value)?)),
            PARLIA_MISBEHAVIOUR_TYPE_URL => {
                Ok(ClientMessage::Misbehaviour(Misbehaviour::try_from(value)?))
            }
            _ => Err(Error::UnexpectedClientType(value.type_url.clone())),
        }
    }
}
