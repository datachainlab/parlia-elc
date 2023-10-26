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

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::header::eth_headers::ETHHeaders;
    use crate::header::testdata::{header_31297201, header_31297202};
    use crate::header::validator_set::ValidatorSet;
    use crate::header::Header;
    use crate::misbehaviour::Misbehaviour;
    use crate::misc::new_height;
    use alloc::string::ToString;
    use hex_literal::hex;
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{
        EthHeader, Misbehaviour as RawMisbehaviour,
    };

    #[test]
    fn test_error_try_from_unexpected_client() {
        let src = RawMisbehaviour {
            client_id: "".to_string(),
            header_1: None,
            header_2: None,
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::UnexpectedClientId(client_id) => assert_eq!(client_id, "".to_string()),
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_missing_h1() {
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: None,
            header_2: None,
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::MissingHeader1 => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_missing_h2() {
        let h = header_31297201();
        let h1 = RawHeader {
            headers: vec![EthHeader {
                header: rlp::encode(&h).to_vec(),
            }],
            trusted_height: Some(Height::default()),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
        };
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: Some(h1),
            header_2: None,
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::MissingHeader2 => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_same_block() {
        let h = header_31297201();
        let h1 = RawHeader {
            headers: vec![EthHeader {
                header: rlp::encode(&h).to_vec(),
            }],
            trusted_height: Some(Height::default()),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
        };
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: Some(h1.clone()),
            header_2: Some(h1),
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::UnexpectedSameBlockHash(height) => assert_eq!(height, new_height(0, h.number)),
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_different_height() {
        let h1_src = header_31297201();
        let h1 = RawHeader {
            headers: vec![EthHeader {
                header: rlp::encode(&h1_src).to_vec(),
            }],
            trusted_height: Some(Height::default()),
            account_proof: vec![],
            current_validators: vec![h1_src.coinbase.clone()],
            previous_validators: vec![h1_src.coinbase.clone()],
        };
        let h2_src = header_31297202();
        let h2 = RawHeader {
            headers: vec![EthHeader {
                header: rlp::encode(&h2_src).to_vec(),
            }],
            trusted_height: Some(Height::default()),
            account_proof: vec![],
            current_validators: vec![h2_src.coinbase.clone()],
            previous_validators: vec![h2_src.coinbase.clone()],
        };
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: Some(h1),
            header_2: Some(h2),
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::UnexpectedDifferentHeight(h1_height, h2_height) => {
                assert_eq!(h1_height, new_height(0, h1_src.number));
                assert_eq!(h2_height, new_height(0, h2_src.number))
            }
            err => unreachable!("{:?}", err),
        }
    }
}
