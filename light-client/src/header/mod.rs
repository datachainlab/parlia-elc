use alloc::vec::Vec;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::commitment::decode_eip1184_rlp_proof;
use crate::consensus_state::ConsensusState;

use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};
use crate::header::eth_header::{validate_turn_length, ETHHeader};

use crate::header::eth_headers::ETHHeaders;
use crate::header::vote_attestation::VoteData;
use crate::misc::{new_height, new_timestamp, BlockNumber, ChainId, Hash};

use super::errors::Error;

use self::constant::BLOCKS_PER_EPOCH;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
pub mod eth_header;
pub mod eth_headers;
pub mod validator_set;
pub mod vote_attestation;

pub mod epoch;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    account_proof: Vec<u8>,
    headers: ETHHeaders,
    trusted_height: Height,
    previous_epoch: Epoch,
    current_epoch: Epoch,
}

impl Header {
    pub fn height(&self) -> Height {
        new_height(
            self.trusted_height.revision_number(),
            self.headers.target.number,
        )
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.headers.target.timestamp)
    }

    pub fn account_proof(&self) -> Result<Vec<Vec<u8>>, Error> {
        decode_eip1184_rlp_proof(&self.account_proof)
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn state_root(&self) -> &Hash {
        &self.headers.target.root
    }

    pub fn previous_epoch_validators_hash(&self) -> Hash {
        self.previous_epoch.hash()
    }

    pub fn current_epoch_validators_hash(&self) -> Hash {
        self.current_epoch.hash()
    }

    pub fn block_hash(&self) -> &Hash {
        &self.headers.target.hash
    }

    pub fn votes(&self) -> Vec<(BlockNumber, VoteData)> {
        let mut votes = vec![];
        for h in self.headers.all.iter() {
            if let Ok(vote) = h.get_vote_attestation() {
                votes.push((h.number, vote.data));
            }
        }
        votes
    }

    pub fn verify(
        &self,
        chain_id: &ChainId,
        consensus_state: &ConsensusState,
    ) -> Result<(), Error> {
        let (c_val, p_val) = verify_epoch(
            consensus_state,
            &self.headers.target,
            self.height(),
            self.trusted_height,
            &self.previous_epoch,
            &self.current_epoch,
        )?;
        self.headers.verify(chain_id, &c_val, &p_val)
    }
}

fn verify_epoch<'a>(
    consensus_state: &ConsensusState,
    target: &ETHHeader,
    height: Height,
    trusted_height: Height,
    previous_epoch: &'a Epoch,
    current_epoch: &'a Epoch,
) -> Result<(EitherEpoch<'a>, TrustedEpoch<'a>), Error> {
    let is_epoch = target.is_epoch();
    let header_epoch = height.revision_height() / BLOCKS_PER_EPOCH;
    let trusted_epoch = trusted_height.revision_height() / BLOCKS_PER_EPOCH;

    if is_epoch {
        if header_epoch != trusted_epoch + 1 {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.current_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedUntrustedValidatorsHashInEpoch(
                trusted_height,
                height,
                previous_epoch.hash(),
                consensus_state.current_validators_hash,
            ));
        }

        let epoch_info = target
            .epoch
            .as_ref()
            .ok_or_else(|| Error::MissingEpochInfoInEpochBlock(target.number))?;
        if epoch_info.hash() != current_epoch.hash() {
            return Err(Error::UnexpectedCurrentValidatorsHashInEpoch(
                trusted_height,
                height,
                epoch_info.hash(),
                current_epoch.hash(),
            ));
        }

        Ok((
            EitherEpoch::Untrusted(UntrustedEpoch::new(current_epoch)),
            TrustedEpoch::new(previous_epoch),
        ))
    } else {
        if header_epoch != trusted_epoch {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.previous_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                height,
                previous_epoch.hash(),
                consensus_state.previous_validators_hash,
            ));
        }
        let current_trusted = current_epoch.hash() == consensus_state.current_validators_hash;
        if !current_trusted {
            return Err(Error::UnexpectedCurrentValidatorsHash(
                trusted_height,
                height,
                current_epoch.hash(),
                consensus_state.current_validators_hash,
            ));
        }
        Ok((
            EitherEpoch::Trusted(TrustedEpoch::new(current_epoch)),
            TrustedEpoch::new(previous_epoch),
        ))
    }
}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(value: RawHeader) -> Result<Header, Self::Error> {
        let trusted_height = value
            .trusted_height
            .as_ref()
            .ok_or(Error::MissingTrustedHeight)?;
        let trusted_height = new_height(
            trusted_height.revision_number,
            trusted_height.revision_height,
        );

        // All the header revision must be same as the revision of trusted_height.
        let headers = ETHHeaders::try_from(value.headers.clone())?;

        if headers.target.number <= trusted_height.revision_height() {
            return Err(Error::UnexpectedTrustedHeight(
                headers.target.number,
                trusted_height.revision_height(),
            ));
        }

        if value.previous_validators.is_empty() {
            return Err(Error::MissingPreviousValidators(headers.target.number));
        }
        validate_turn_length(value.previous_turn_length as u8)?;

        // Epoch header contains validator set
        let current_epoch = if headers.target.is_epoch() {
            headers
                .target
                .epoch
                .clone()
                .ok_or_else(|| Error::MissingEpochInfoInEpochBlock(headers.target.number))?
        } else {
            Epoch::new(
                value.current_validators.into(),
                value.current_turn_length as u8,
            )
        };
        if current_epoch.validators().is_empty() {
            return Err(Error::MissingCurrentValidators(headers.target.number));
        }
        validate_turn_length(value.current_turn_length as u8)?;

        Ok(Self {
            account_proof: value.account_proof,
            headers,
            trusted_height,
            previous_epoch: Epoch::new(
                value.previous_validators.into(),
                value.previous_turn_length as u8,
            ),
            current_epoch,
        })
    }
}

impl TryFrom<IBCAny> for Header {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header, Self::Error> {
        if any.type_url != PARLIA_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl TryFrom<Any> for Header {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;

    use crate::fixture::*;
    use crate::header::epoch::{EitherEpoch, Epoch};
    use crate::header::eth_headers::ETHHeaders;
    use crate::header::validator_set::ValidatorSet;
    use crate::header::{verify_epoch, Header};
    use crate::misc::{new_height, Hash, Validators};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use hex_literal::hex;
    use light_client::types::{Any, Height as LCPHeight, Time};
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{EthHeader, Header as RawHeader};
    use rstest::rstest;

    impl Header {
        pub(crate) fn eth_header(&self) -> &ETHHeaders {
            &self.headers
        }

        pub(crate) fn new(
            account_proof: Vec<u8>,
            headers: ETHHeaders,
            trusted_height: Height,
            previous_epoch: Epoch,
            current_epoch: Epoch,
        ) -> Self {
            Self {
                account_proof,
                headers,
                trusted_height: LCPHeight::new(
                    trusted_height.revision_number,
                    trusted_height.revision_height,
                ),
                previous_epoch,
                current_epoch,
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_trusted_height(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: None,
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingTrustedHeight => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_trusted_height(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height.clone()),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(number, trusted_number) => {
                assert_eq!(number, h.number);
                assert_eq!(trusted_number, trusted_height.revision_height);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_previous_validators_is_empty(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingPreviousValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_current_validators_is_empty(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height),
            account_proof: vec![],
            current_validators: vec![],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingCurrentValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_try_from(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_rlp(),
            }],
            trusted_height: Some(trusted_height.clone()),
            account_proof: vec![],
            current_validators: hp.epoch_header().epoch.unwrap().validators().clone(),
            previous_validators: hp.previous_validators(),
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let result = Header::try_from(raw.clone()).unwrap();
        assert_eq!(result.headers.target, *h);
        assert_eq!(
            result.trusted_height.revision_height(),
            trusted_height.revision_height
        );
        assert_eq!(
            result.trusted_height.revision_number(),
            trusted_height.revision_number
        );
        assert_eq!(result.previous_epoch.validators(), &raw.previous_validators);
        assert_eq!(result.current_epoch.validators(), &raw.current_validators);
    }

    fn to_validator_set(h: Hash) -> ValidatorSet {
        let validators: Validators = vec![vec![1]];
        let mut v: ValidatorSet = validators.into();
        v.hash = h;
        v
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_validator_set(#[case] hp: Box<dyn Network>) {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };

        // epoch
        let height = new_height(0, 400);
        let trusted_height = new_height(0, 201);
        let current_epoch = &hp.epoch_header().epoch.unwrap();
        let previous_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let (c_val, p_val) = verify_epoch(
            &cs,
            &hp.epoch_header(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap();
        match c_val {
            EitherEpoch::Untrusted(r) => {
                assert!(r.try_borrow(&p_val).is_err())
            }
            _ => unreachable!("unexpected trusted"),
        }

        // not epoch
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };
        let height = new_height(0, 599);
        let trusted_height = new_height(0, 400);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let (c_val, _p_val) = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap();
        match c_val {
            EitherEpoch::Trusted(r) => {
                assert_eq!(r.validators(), current_epoch.validators());
            }
            _ => unreachable!("unexpected untrusted"),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_validator_set(#[case] hp: Box<dyn Network>) {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };

        let height = new_height(0, 400);
        let trusted_height = new_height(0, 199);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(t, h) => {
                assert_eq!(t, trusted_height.revision_height());
                assert_eq!(h, height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 200);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedUntrustedValidatorsHashInEpoch(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cs.current_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let height = new_height(0, 401);
        let trusted_height = new_height(0, 200);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(t, h) => {
                assert_eq!(t, trusted_height.revision_height());
                assert_eq!(h, height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 400);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([3u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cs.previous_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 400);
        let current_epoch = &Epoch::new(to_validator_set([3u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, current_epoch.hash());
                assert_eq!(cons_hash, cs.current_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([4u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };
        let height = new_height(0, 400);
        let trusted_height = new_height(0, 399);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([4u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHashInEpoch(t, h, header_hash, request_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(header_hash, hp.epoch_header().epoch.unwrap().hash());
                assert_eq!(request_hash, current_epoch.hash());
            }
            _ => unreachable!("err {:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_invalid_turn_length() {
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212961e0a9e060a9b06f90318a0793f4896c559772686c55bc1140baa291e62ef268061713080c9d02193ecd549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d1d6bf74282782b0b3eb1413c901d6ecf02e8e28a0c2081e9bb02adf2b65cf9b3f83b71142e4a963584516174fa671c75e3c9b82f0a071f511f91544d703b0a8a74ef6b93df3d261d961b15f5abb688a115a164f59aba0a93cf4b9598e6c8ff24b4aea19f8a64291de129c57118291fee8c4b16de22fe5b90100462586c2f1cfbc9f58faae6f8ff10b2b6a5e6acb0d3077c87e9b05031ab93d1e8f62b32a766618ad9af4b9a1629f42008273c409768e35be70154b2721e87ef585d19504837158efa1b705d99333122ea79c48b387729b7e491f8154d55c5f180e6d01668a76152594e3183ccae8490d8e8e92500e0f5c2ad6b0e415f45ac72f95fab24672835de1c48e0a9f38923ec496ae5dd5fb62043cfd7bc0c8f0c5c3f1670ef7d1d7fc2b907ffe63ced34467b8fbf2300dba03b63a57722ff07ae56961f52d1a32862a09ef3698d1b93bc636286a56b3cadb8b22998372f4c28cd1e72c7ab0f0ab0db8c6aa8105556c1a3481c6fc66ac24d5ae775fba850d343a210feb028401e6aa4184084fe2c684014933a184650a4afbb90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831dffffb8609865f38b886fdf9133435031ff4e3af35f0f7dcd165bed2f80f523864cdcaacd102a5d538972060573218a8cbd201d9418fde9d217990d8faf5c5c382618820fe24cf490f1010d92a66114d3d5305e953ef00268448068d5fb4638a94c4269a2f84c8401e6aa3fa0cba1480655a9172eb8fc0a0ea9cd5a285b9fcea8489bde764a134c52a8cc0ff98401e6aa40a0793f4896c559772686c55bc1140baa291e62ef268061713080c9d02193ecd54980a72fc8f10e414df8a61ea1d4d2f3362b2fa0c8c7c444848769e6d67bdbcce4de2683fdae80bcd5a90a8f92d76b7ae426f11d51a7f1d785fefe1cbf451f67186401a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9a060a9706f90314a094904149695c8adb89cd6f020cb278275a2fd4483cfc10d7d3dab8121f69f306a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e9ae3261a475a27bb1028f140bc2a7c843318afda0c2081e9bb02adf2b65cf9b3f83b71142e4a963584516174fa671c75e3c9b82f0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028401e6aa4284085832a78084650a4affb90118d88301020a846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831dffffb860b02f4314b40616294282cb1f66df8eb23b1c26395b214e78ecd75a9646e0fd008b5f9bae4b24647db4f4b4a92ca0aee4032f3a8917546bfc7c078624ab1b0be6bf87972f4d9815f4f96ad00ba291308ee5c5f6c63243e9518ab6c1f42ce34470f84c8401e6aa40a0793f4896c559772686c55bc1140baa291e62ef268061713080c9d02193ecd5498401e6aa41a094904149695c8adb89cd6f020cb278275a2fd4483cfc10d7d3dab8121f69f30680ec8e7cec4b6c25fa8b22c40e9ecae359c542137ed189c711f5cd7616f4619f331f3eb09268047aaf47af3b83786ee4471c31779848627720f48a7bf5ca50f14601a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800ae6040ae304f90260a0cadbcaaebd901c23537425e903b40a054d6cca192f0f01ecf3d45d9afce4cef3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea0a6e3c511bbd10f4519ece37dc24887e11b55da054d3ce938c69efbd57808ae22c9030bfa64ebfe6b7f16d5574b1fada5c336d96a0ba3499b3199bc9606a46f865d4abc0cfa9e1be68940ba8a91eb0de4e02d660f5a04278f75943cad9584a22440799ef5f5db6618e33bed532b709b859bb44e0d02fb901006eb746324da2c67a4c1a4a70aeed04073c9d207629cda74bd61604bf345053d797915346c4e531f9033b2df9067732f89d89f3e90b6ae92122c64c020964e7de5facd5784b66c76ac979829d886e8779f9b1f4b5e5efd954c956a916bb1d5f71937998aa33863da5ace9aa48432959190bfee853e57f55beeae4c6b8efcc0ff092f7f1f73afcd1daf3dcbb7c3f82fab45bacbc95366ad9fc6d495e5968e65c346248d49a759b29086e28a57f6af62769dfac85aba6ddf3013783b02ad9d872e8afa60d631a9f0c838298a5955222d611e3d1b79eb8a872beaa37fa5a9a00e50dabd0ca073bc1ff981bf906c0fda18164ae868587e9b802cdf7e26fae9a811f0b028401e6aa438408583b00840105fdbe84650a4b02b861d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a239e14e61ceb442e61edd782ed2e011994aca0236541d845851453ed45e1c950b3672dcc21546bd65e746c468b17a3722b7c529d64d9c3a4b41136ab03e48147e01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9e060a9b06f90318a0cc482c7a97c2c547a7e1483c14e65bb6087ca7257c15ff673f946298c57e7d90a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ee226379db83cffc681495730c11fdde79ba4c0ca0921e5a9881b361b462e86c18d8170303f37f3576c4298f951b164a3a0ffa7950a04a318f22b6185bdebef3900d7c65bcceed28c6906605406b54bd9eb07cb6a266a07a8d59ef980eed078ac8f192425c1fffbf5210a9c92a2065c40639f6421c2367b90100cae58a5a44a877dfab933564fb46b73ec4c3d9c7f068cd492e7b13a3d43cca90ce095bebe264c59a13537dd3575e47c5a87922ba687d73fbdf4cf75c5c7fae998edcc9956b64445fc973aacd815ef67bbc3ce25deb67e19207fff0d98cc0cd558a0ec9eb2bb7bee5b4e736041f80bdcb0862fbf2e9afff5e3ce0959b8fa1cfb795fe04f69cbfecdde7a927c01fe87cc89cad2e277b31e63a5619f6ffac97cb631f4ba69ce7fea3f16e3c2b15fb8b2462cbf6ef9b62b3e77173fb306f19eb12fbe2ecdedfb32acbcf3efa25d9f79838b2b76b25cec051447eab71740e862feb2fd214e4db5568ceb4a791b6bec6c1a972726641bce9fe4f68e46edf15df75e652028401e6aa448408583b00840107e57384650a4b05b90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5831dffffb860a4cc53efef08386da2bcdf2ccd02f5772899f7e1f3b0252b21bf309dd6f96034ee6570316f1767c75acdd7f6691589051341d1cdf1f118c5c47c505a2e48a47da6e7d26c3107799b8cf767cff1382115896c6b74f0df094690ee36d0fcecf95ef84c8401e6aa41a094904149695c8adb89cd6f020cb278275a2fd4483cfc10d7d3dab8121f69f3068401e6aa43a0cc482c7a97c2c547a7e1483c14e65bb6087ca7257c15ff673f946298c57e7d908093e10e56b7f84c8f756b3bd5422d93053db5f5a55dee436bae6d8066674e131f4f430278fc3cb1f4d9f3dd0c85410694b92887718d431d8ddf25524ece35d03501a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a04eedf58a08358d43f0d37410f1c301efcc3dd738eff0b07bb4f82c83f30a0cc2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda04773baafa2984559c063e6b1f50e3019baae941124e89d5d7bc3f009e484a3d0a0c350e76080e62e8e4f45c1d424daec63750b940344655e81f56f0c65f1e7ab40a0cfd21dbf9df8503fb97bcd511aa04483116eb7afd0d4702532d1ff0b8e8b849eb90100002e022444181418d2d2414984070420434880e00f19494c8452044a5a7001298681544650c412916e119ca3241220808c0110050418214674422800002620a06440c08029440f8f296082ac8214002db995a0c59de7580a06168014c01036205a8ca0628e8205000458ea6110210d480a002ce0809e0410430084100d4c6420390a20a40479e91a14982410089018c4902ca40d601091081181105024a110a007904082087e211261d6008c42ceb44942602191022801165326a8aa1f8f28f8e0262c92228732026080028c8812d2057a10b884800048b10c13545b9e20f6340ab485c910af5a940909064e044f41446c6b8581653051e81603b101fc498c0b028401e6aa458408583b008385259f84650a4b08b90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5831dffffb86088dd96fd990be352a39175463f3902ec9f4f036ed7cd8ab3ce3f4cc70dfc8230a1a1f856e28cbc84a4ed1f95431f63cd0464f1c2f061593bfaf3eae388264d02420af41cfc0e01525f438bc3cf11b9c5a988aa6bb9c82098d567b339709ac676f84c8401e6aa43a0cc482c7a97c2c547a7e1483c14e65bb6087ca7257c15ff673f946298c57e7d908401e6aa44a04eedf58a08358d43f0d37410f1c301efcc3dd738eff0b07bb4f82c83f30a0cc2801962735bca49e800156401aa4bbe2e32d58f36cc22ce3cfd8da23ca72e10eb2f44fa1c1a1840959059d86e6f1b936457795534d45c8a554c3060e9dd39ec108001a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801200221400000000000000000000000000000000000000002a140000000000000000000000000000000000000000").to_vec();
        let any: Any = header.try_into().unwrap();
        let err = Header::try_from(any).unwrap_err();
        match err {
            Error::UnexpectedTurnLength(turn_length) => {
                assert_eq!(turn_length, 0)
            }
            _ => unreachable!("unexpected "),
        }
    }
}
