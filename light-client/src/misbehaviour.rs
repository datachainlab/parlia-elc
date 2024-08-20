use core::str::FromStr;

use light_client::types::{Any, ClientId};
use prost::Message;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Misbehaviour as RawMisbehaviour;

use crate::errors::Error;
use crate::header::vote_attestation::VoteData;
use crate::header::Header;
use crate::misc::BlockNumber;

pub const PARLIA_MISBEHAVIOUR_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Misbehaviour";

#[derive(Clone, Debug, PartialEq)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
}

#[derive(Debug)]
pub enum VerifyVoteResult {
    SourceNumber(BlockNumber, BlockNumber, BlockNumber),
    TargetNumber(BlockNumber, BlockNumber, BlockNumber),
    Range(BlockNumber, BlockNumber),
}

impl Misbehaviour {
    pub fn verify(&self) -> Result<(), Error> {
        let h1 = &self.header_1;
        let h2 = &self.header_2;
        if h1.height() == h2.height() {
            // exactly same block is not misbehavior
            if h1.block_hash() == h2.block_hash() {
                return Err(Error::UnexpectedSameBlockHash(
                    h1.height(),
                    h2.height(),
                    *h1.block_hash(),
                ));
            }
            return Ok(());
        }
        let _ = self.verify_votes()?;
        Ok(())
    }

    fn verify_votes(&self) -> Result<VerifyVoteResult, Error> {
        let h1 = &self.header_1;
        let h2 = &self.header_2;
        for (h1_num, v1) in h1.votes() {
            for (h2_num, v2) in h2.votes() {
                if let Some(result) = verify_vote(h1_num, &v1, h2_num, &v2) {
                    return Ok(result);
                }
            }
        }
        Err(Error::UnexpectedHonestVote(h1.height(), h2.height()))
    }
}

fn verify_vote(
    h1_num: BlockNumber,
    v1: &VoteData,
    h2_num: BlockNumber,
    v2: &VoteData,
) -> Option<VerifyVoteResult> {
    if h1_num == h2_num {
        return None;
    }

    // source number is unique in finalized blocks
    if v1.source_number == v2.source_number {
        return Some(VerifyVoteResult::SourceNumber(
            h1_num,
            h2_num,
            v1.source_number,
        ));
    }
    // https://github.com/bnb-chain/BEPs/blob/master/BEPs/BEP126.md#411-validator-vote-rules
    // Check rule 1
    if v1.target_number == v2.target_number {
        return Some(VerifyVoteResult::TargetNumber(
            h1_num,
            h2_num,
            v1.target_number,
        ));
    }
    // Check rule 2
    if (v1.source_number < v2.source_number && v2.target_number < v1.target_number)
        || (v2.source_number < v1.source_number && v1.target_number < v2.target_number)
    {
        return Some(VerifyVoteResult::Range(h1_num, h2_num));
    }
    None
}

impl TryFrom<RawMisbehaviour> for Misbehaviour {
    type Error = Error;

    fn try_from(value: RawMisbehaviour) -> Result<Self, Self::Error> {
        let client_id = ClientId::from_str(&value.client_id)
            .map_err(|_| Error::UnexpectedClientId(value.client_id))?;

        let header_1 = Header::try_from(value.header_1.ok_or(Error::MissingHeader1)?)?;
        let header_2 = Header::try_from(value.header_2.ok_or(Error::MissingHeader2)?)?;

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
    use crate::header::eth_header::ETHHeader;

    use crate::fixture::*;

    use crate::header::epoch::Epoch;
    use crate::header::eth_headers::ETHHeaders;
    use crate::header::vote_attestation::VoteData;
    use crate::header::Header;
    use crate::misbehaviour::{verify_vote, Misbehaviour, VerifyVoteResult};
    use crate::misc::new_height;
    use alloc::string::ToString;
    use core::str::FromStr;
    use light_client::types::ClientId;
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Misbehaviour as RawMisbehaviour;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{EthHeader, Header as RawHeader};
    use rstest::rstest;
    use std::prelude::rust_2015::Box;

    fn to_raw(h: alloc::vec::Vec<u8>) -> RawHeader {
        RawHeader {
            headers: vec![EthHeader { header: h }],
            trusted_height: Some(Height::default()),
            account_proof: vec![],
            current_validators: vec![vec![0]],
            previous_validators: vec![vec![0]],
            previous_turn_length: 1,
            current_turn_length: 1,
        }
    }

    fn make_header(h: ETHHeader) -> Header {
        Header::new(
            vec![],
            ETHHeaders {
                target: h.clone(),
                all: vec![h],
            },
            Height::default(),
            Epoch::new(vec![vec![0]].into(), 1),
            Epoch::new(vec![vec![0]].into(), 1),
        )
    }

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

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_h2(#[case] hp: Box<dyn Network>) {
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: Some(to_raw(hp.epoch_header_plus_1_rlp())),
            header_2: None,
        };
        match Misbehaviour::try_from(src).unwrap_err() {
            Error::MissingHeader2 => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_try_from(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header();
        let h2 = hp.epoch_header_plus_1();
        let src = RawMisbehaviour {
            client_id: "xx-parlia-1".to_string(),
            header_1: Some(to_raw(hp.epoch_header_rlp())),
            header_2: Some(to_raw(hp.epoch_header_plus_1_rlp())),
        };
        let misbehaviour = Misbehaviour::try_from(src).unwrap();
        assert_eq!(misbehaviour.client_id.as_str(), "xx-parlia-1");
        assert_eq!(misbehaviour.header_1.height(), new_height(0, h1.number));
        assert_eq!(misbehaviour.header_2.height(), new_height(0, h2.number));
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify(#[case] hp: Box<dyn Network>) {
        let h1 = make_header(hp.epoch_header());
        let mut h2 = hp.epoch_header();
        h2.hash = [0u8; 32];
        let h2 = make_header(h2);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::from_str("xx-parlia-1").unwrap(),
            header_1: h1,
            header_2: h2,
        };
        misbehaviour.verify().unwrap();
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_same_block(#[case] hp: Box<dyn Network>) {
        let h1 = Header::try_from(to_raw(hp.epoch_header_rlp())).unwrap();
        let misbehaviour = Misbehaviour {
            client_id: ClientId::from_str("xx-parlia-1").unwrap(),
            header_1: h1.clone(),
            header_2: h1.clone(),
        };
        match misbehaviour.verify().unwrap_err() {
            Error::UnexpectedSameBlockHash(e1, e2, e3) => {
                assert_eq!(e1, h1.height());
                assert_eq!(e2, h1.height());
                assert_eq!(e3, *h1.block_hash());
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_other_height(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header();
        let h2 = hp.epoch_header_plus_1();
        let h1 = make_header(h1);
        let h2 = make_header(h2);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::from_str("xx-parlia-1").unwrap(),
            header_1: h1.clone(),
            header_2: h2.clone(),
        };
        match misbehaviour.verify().unwrap_err() {
            Error::UnexpectedHonestVote(e1, e2) => {
                assert_eq!(e1, h1.height());
                assert_eq!(e2, h2.height());
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_vote_same_height(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header();
        let mut h2 = hp.epoch_header();
        h2.hash = [0u8; 32];
        let h1 = make_header(h1);
        let h2 = make_header(h2);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::from_str("xx-parlia-1").unwrap(),
            header_1: h1.clone(),
            header_2: h2.clone(),
        };
        match misbehaviour.verify_votes().unwrap_err() {
            Error::UnexpectedHonestVote(e1, e2) => {
                assert_eq!(e1, h1.height());
                assert_eq!(e2, h2.height());
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_vote_source_number(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header_plus_1();
        let mut h2 = hp.epoch_header_plus_2();
        h2.extra_data = h1.clone().extra_data;
        let h1 = make_header(h1);
        let h2 = make_header(h2);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::from_str("xx-parlia-1").unwrap(),
            header_1: h1.clone(),
            header_2: h2.clone(),
        };
        match misbehaviour.verify_votes().unwrap() {
            VerifyVoteResult::SourceNumber(n1, n2, s) => {
                assert_eq!(n1, h1.height().revision_height());
                assert_eq!(n2, h2.height().revision_height());
                assert_eq!(
                    s,
                    h1.eth_header()
                        .target
                        .get_vote_attestation()
                        .unwrap()
                        .data
                        .source_number
                )
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_vote_target_number(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header_plus_1();
        let v1 = h1.get_vote_attestation().unwrap().data;
        let h2 = hp.epoch_header_plus_2();
        let mut v2 = h2.get_vote_attestation().unwrap().data;
        v2.target_number = v1.target_number;
        match verify_vote(h1.number, &v1, h2.number, &v2).unwrap() {
            VerifyVoteResult::TargetNumber(n1, n2, s) => {
                assert_eq!(n1, h1.number);
                assert_eq!(n2, h2.number);
                assert_eq!(s, v1.target_number)
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_vote_range(#[case] hp: Box<dyn Network>) {
        let h1 = hp.epoch_header_plus_1();
        let v1 = h1.get_vote_attestation().unwrap().data;
        let h2 = hp.epoch_header_plus_2();

        let verify = |v1: &VoteData, v2: &VoteData| {
            match verify_vote(h1.number, v1, h2.number, v2).unwrap() {
                VerifyVoteResult::Range(n1, n2) => {
                    assert_eq!(n1, h1.number);
                    assert_eq!(n2, h2.number);
                }
                err => unreachable!("{:?}", err),
            };
        };
        let mut v2 = h2.get_vote_attestation().unwrap().data;
        v2.source_number = v1.source_number - 1;
        v2.target_number = v1.target_number + 1;
        verify(&v1, &v2);

        let mut v2 = h2.get_vote_attestation().unwrap().data;
        v2.source_number = v1.source_number + 1;
        v2.target_number = v1.target_number - 1;
        verify(&v1, &v2);
    }
}
