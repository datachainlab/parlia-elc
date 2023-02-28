use alloc::boxed::Box;
use alloc::str::FromStr;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use commitments::{gen_state_id_from_any, StateCommitment, StateID, UpdateClientCommitment};
use crypto::Keccak256;
use ibc::core::ics02_client::client_state::ClientState as _;
use ibc::core::ics02_client::client_state::ClientState as _;
use ibc::core::ics02_client::consensus_state::ConsensusState as _;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as IBCHeader;
use ibc::core::ics02_client::header::Header as _;
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::ClientId;
use ibc::core::ics24_host::Path;
use ibc_proto::google::protobuf::Any as IBCAny;
use lcp_types::{Any, Height};
use light_client::{
    ClientReader, CreateClientResult, Error as LightClientError, LightClient,
    StateVerificationResult, UpdateClientResult,
};
use light_client_registry::LightClientRegistry;
use validation_context::ValidationParams;

use parlia_ibc_lc::client_def::ParliaClient;
use parlia_ibc_lc::client_state::{ClientState, PARLIA_CLIENT_STATE_TYPE_URL};
use parlia_ibc_lc::consensus_state::ConsensusState;
use parlia_ibc_lc::header::Header;
use parlia_ibc_lc::misc::{ValidatorReader, Validators};
use parlia_ibc_lc::path::YuiIBCPath;

use crate::errors::Error;

#[derive(Default)]
pub struct ParliaLightClient(ParliaClient);

pub fn register_implementations(registry: &mut dyn LightClientRegistry) {
    registry
        .put_light_client(
            String::from(PARLIA_CLIENT_STATE_TYPE_URL),
            Box::new(ParliaLightClient(ParliaClient)),
        )
        .unwrap()
}

impl LightClient for ParliaLightClient {
    fn client_type(&self) -> String {
        ClientState::client_type().to_string()
    }

    fn latest_height(
        &self,
        ctx: &dyn ClientReader,
        client_id: &ClientId,
    ) -> Result<Height, LightClientError> {
        let any_client_state = read_client_state(ctx, client_id)?;
        let client_state: ClientState = try_from_any(any_client_state)?;
        Ok(client_state.latest_height().into())
    }

    fn create_client(
        &self,
        _ctx: &dyn ClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, LightClientError> {
        let new_state_id = state_id(&any_client_state, &any_consensus_state)?;
        let client_state: ClientState = try_from_any(any_client_state.clone())?;
        let consensus_state: ConsensusState = try_from_any(any_consensus_state)?;

        let height = client_state.latest_height().into();
        let timestamp = consensus_state.timestamp().into();

        Ok(CreateClientResult {
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: None,
                new_state_id,
                new_state: Some(any_client_state),
                prev_height: None,
                new_height: height,
                timestamp,
                validation_params: ValidationParams::Empty,
            },
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        any_header: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        //Ensure header can be verified.
        let header: Header = try_from_any(any_header)?;
        let now = ctx.host_timestamp();
        let trusted_height = header.trusted_height();
        let any_client_state = read_client_state(ctx, &client_id)?;
        let any_consensus_state = read_consensus_state(ctx, &client_id, trusted_height.into())?;
        let prev_state_id = state_id(&any_client_state, &any_consensus_state)?;

        //Ensure client is not frozen
        let client_state: ClientState = try_from_any(any_client_state)?;
        if client_state.is_frozen() {
            return Err(LightClientError::ics02(ClientError::ClientFrozen {
                client_id,
            }));
        }

        // Create new state and ensure header is valid
        let consensus_state: ConsensusState = try_from_any(any_consensus_state)?;
        let ctx = DefaultValidatorReader {
            ctx,
            client_id: &client_id,
        };
        let (new_client_state, new_consensus_state) = self
            .0
            .check_header_and_update_state(ctx, now, &client_state, &consensus_state, &header)
            .map_err(Error::ParliaIBCLC)?;

        let new_height = new_client_state.latest_height.into();
        let new_any_client_state = into_any(new_client_state);
        let new_any_consensus_state = into_any(new_consensus_state);
        let new_state_id = state_id(&new_any_client_state, &new_any_consensus_state)?;

        Ok(UpdateClientResult {
            new_any_client_state,
            new_any_consensus_state,
            height: header.height().into(),
            commitment: UpdateClientCommitment {
                prev_state_id: Some(prev_state_id),
                new_state_id,
                new_state: None,
                prev_height: Some(header.trusted_height().into()),
                new_height,
                timestamp: header.timestamp().into(),
                validation_params: ValidationParams::Empty,
            },
            prove: true,
        })
    }

    fn verify_membership(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: Vec<u8>,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let (prefix, path) = apply_prefix(prefix, &path)?;

        // Do not keccak already keccaked values such as commitment packets
        let value = match path {
            Path::Commitment(_) => value,
            _ => value.keccak256().to_vec(),
        };
        let mut result = self.verify_commitment(
            ctx,
            client_id,
            prefix,
            path,
            Some(value.clone()),
            proof_height,
            proof,
        )?;
        result.state_commitment.value =
            Some(value.try_into().map_err(Error::UnexpectedCommitmentValue)?);
        Ok(result)
    }

    fn verify_non_membership(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: Vec<u8>,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let (prefix, path) = apply_prefix(prefix, &path)?;
        self.verify_commitment(ctx, client_id, prefix, path, None, proof_height, proof)
    }
}

impl ParliaLightClient {
    #[allow(clippy::too_many_arguments)]
    fn verify_commitment(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: Path,
        value: Option<Vec<u8>>,
        proof_height: Height,
        storage_proof_rlp: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let any_client_state = read_client_state(ctx, &client_id)?;
        let client_state: ClientState = try_from_any(any_client_state.clone())?;
        if client_state.is_frozen() {
            return Err(LightClientError::ics02(ClientError::ClientFrozen {
                client_id,
            }));
        }
        if Height::from(client_state.latest_height()) != proof_height {
            return Err(Error::UnexpectedHeight(proof_height).into());
        }

        let any_consensus_state = read_consensus_state(ctx, &client_id, proof_height)?;

        let consensus_state: ConsensusState = try_from_any(any_consensus_state.clone())?;
        let storage_root = consensus_state.state_root().map_err(Error::ParliaIBCLC)?;
        self.0
            .verify_commitment(
                &storage_root,
                &storage_proof_rlp,
                YuiIBCPath::from(path.to_string().as_bytes()),
                &value,
            )
            .map_err(Error::ParliaIBCLC)?;

        let state_id = state_id(&any_client_state, &any_consensus_state)?;

        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(prefix, path, None, proof_height, state_id),
        })
    }
}

fn state_id(client_state: &Any, consensus_state: &Any) -> Result<StateID, LightClientError> {
    gen_state_id_from_any(client_state, consensus_state).map_err(LightClientError::commitment)
}

fn read_client_state(
    ctx: &dyn ClientReader,
    client_id: &ClientId,
) -> Result<Any, LightClientError> {
    ctx.client_state(client_id).map_err(LightClientError::ics02)
}

fn read_consensus_state(
    ctx: &dyn ClientReader,
    client_id: &ClientId,
    height: Height,
) -> Result<Any, LightClientError> {
    ctx.consensus_state(client_id, height)
        .map_err(LightClientError::ics02)
}

fn try_from_any<T: TryFrom<IBCAny, Error = ClientError>>(any: Any) -> Result<T, LightClientError> {
    let any: IBCAny = any.into();
    any.try_into().map_err(LightClientError::ics02)
}

fn into_any<T: Into<IBCAny>>(src: T) -> Any {
    let any: IBCAny = src.into();
    any.into()
}

fn apply_prefix(prefix: Vec<u8>, path: &str) -> Result<(CommitmentPrefix, Path), Error> {
    let prefix = prefix.try_into().map_err(Error::ICS23)?;
    //TODO apply prefix if needed
    let path = Path::from_str(path).map_err(Error::Path)?;
    Ok((prefix, path))
}

struct DefaultValidatorReader<'a> {
    ctx: &'a dyn ClientReader,
    client_id: &'a ClientId,
}

impl<'a> ValidatorReader for DefaultValidatorReader<'a> {
    fn read(&self, ibc_height: ibc::Height) -> Result<Validators, parlia_ibc_lc::errors::Error> {
        let height = Height::new(ibc_height.revision_number(), ibc_height.revision_height());
        let consensus_state = self
            .ctx
            .consensus_state(self.client_id, height)
            .map_err(parlia_ibc_lc::errors::Error::ICS02Error)?;
        let consensus_state: ConsensusState = try_from_any(consensus_state)
            .map_err(|_e| parlia_ibc_lc::errors::Error::UnexpectedAnyConsensusState(ibc_height))?;
        Ok(consensus_state.validator_set)
    }
}

#[cfg(test)]
mod test {
    use alloc::string::{String, ToString};
    use alloc::vec;

    use core::str::FromStr;

    use hex_literal::hex;
    use ibc::core::ics02_client::error::ClientError;
    use ibc::core::ics02_client::header::Header;
    use ibc::core::ics23_commitment::commitment::CommitmentRoot;
    use ibc::core::ics24_host::identifier::ClientId;
    use ibc::core::ics24_host::Path;
    use ibc::timestamp::Timestamp;
    use lcp_types::{Any, Height};
    use light_client::{ClientReader, LightClient};

    use parlia_ibc_lc::client_state::ClientState;
    use parlia_ibc_lc::consensus_state::ConsensusState;

    use parlia_ibc_lc::header;
    use parlia_ibc_lc::header::testdata::{
        create_epoch_block, create_previous_epoch_block, fill, to_rlp,
    };
    use parlia_ibc_lc::misc::{
        new_ibc_height, new_ibc_height_with_chain_id, new_ibc_timestamp, ChainId,
    };

    use crate::client::{into_any, try_from_any, ParliaLightClient};

    struct MockClientReader;

    impl ClientReader for MockClientReader {
        fn client_type(&self, _client_id: &ClientId) -> Result<String, ClientError> {
            todo!()
        }

        fn client_state(&self, client_id: &ClientId) -> Result<Any, ClientError> {
            let mainnet = ChainId::new(56);
            let cs = if client_id.as_str() == "99-bscchain-0" {
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: new_ibc_height(1, 2).unwrap(),
                    trust_level: Default::default(),
                    trusting_period: 1_000_000_000,
                    frozen: false,
                }
            } else {
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: new_ibc_height(1, 1).unwrap(),
                    trust_level: Default::default(),
                    trusting_period: 1_000_000_000,
                    frozen: false,
                }
            };
            Ok(into_any(cs))
        }

        fn consensus_state(
            &self,
            _client_id: &ClientId,
            height: Height,
        ) -> Result<Any, ClientError> {
            let current_epoch = fill(create_epoch_block());
            let previous_epoch = fill(create_previous_epoch_block());
            if height.revision_height() == 1 {
                Ok(into_any(ConsensusState {
                    state_root: CommitmentRoot::from_bytes(&[]),
                    timestamp: self.host_timestamp(),
                    validator_set: vec![],
                }))
            } else if height.revision_height() == 2 {
                Ok(into_any(ConsensusState {
                    state_root: CommitmentRoot::from_bytes(&hex!(
                        "c7c2351e84411a86c7165856578a0668fddfe77e30d63965184af89dfb192f18"
                    )),
                    timestamp: self.host_timestamp(),
                    validator_set: vec![],
                }))
            } else if height.revision_height() == current_epoch.number {
                Ok(into_any(ConsensusState {
                    state_root: CommitmentRoot::from_bytes(&current_epoch.root),
                    timestamp: new_ibc_timestamp(current_epoch.timestamp).unwrap(),
                    validator_set: current_epoch.new_validators,
                }))
            } else if height.revision_height() == previous_epoch.number {
                Ok(into_any(ConsensusState {
                    state_root: CommitmentRoot::from_bytes(&previous_epoch.root),
                    timestamp: new_ibc_timestamp(previous_epoch.timestamp).unwrap(),
                    validator_set: previous_epoch.new_validators,
                }))
            } else {
                panic!("no consensus state found {:?}", height);
            }
        }

        fn host_height(&self) -> Height {
            todo!()
        }

        fn host_timestamp(&self) -> Timestamp {
            header::testdata::create_after_checkpoint_headers().timestamp()
        }

        fn client_counter(&self) -> Result<u64, ClientError> {
            todo!()
        }
    }

    #[test]
    fn test_create_client() {
        let client = ParliaLightClient::default();
        let ctx = MockClientReader {};

        let mainnet = ChainId::new(56);
        let client_state = ClientState {
            chain_id: mainnet.clone(),
            ibc_store_address: [0; 20],
            latest_height: new_ibc_height_with_chain_id(&mainnet, 1).unwrap(),
            trust_level: Default::default(),
            trusting_period: 0,
            frozen: false,
        };
        let consensus_state = ConsensusState {
            state_root: CommitmentRoot::from_bytes(&[0; 32]),
            timestamp: new_ibc_timestamp(1677130449 * 1_000_000_000).unwrap(),
            validator_set: vec![],
        };
        let any_client_state = into_any(client_state.clone());
        let any_consensus_state = into_any(consensus_state.clone());
        match client.create_client(&ctx, any_client_state.clone(), any_consensus_state) {
            Ok(result) => {
                assert_eq!(result.height, client_state.latest_height.into());
                assert_eq!(
                    result.commitment.timestamp,
                    consensus_state.timestamp.into()
                );
                assert_eq!(result.commitment.prev_height, None);
                assert_eq!(result.commitment.prev_state_id, None);
                assert_eq!(
                    result.commitment.new_height,
                    client_state.latest_height.into()
                );
                assert_eq!(result.commitment.new_state.unwrap(), any_client_state);
                assert!(!result.commitment.new_state_id.to_vec().is_empty());
            }
            Err(e) => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_update_client() {
        let ctx = MockClientReader;
        let client = ParliaLightClient::default();

        let header = header::testdata::create_after_checkpoint_headers();
        match client.update_client(&ctx, ClientId::default(), into_any(header.clone())) {
            Ok(data) => {
                let new_client_state: ClientState =
                    try_from_any(data.new_any_client_state).unwrap();
                let new_consensus_state: ConsensusState =
                    try_from_any(data.new_any_consensus_state).unwrap();
                assert_eq!(data.height, header.height().into());
                assert_eq!(new_client_state.latest_height, header.height());
                assert_eq!(
                    new_consensus_state.state_root.as_bytes(),
                    hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                );
                assert_eq!(new_consensus_state.timestamp, header.timestamp());
                assert!(new_consensus_state.validator_set.is_empty());
                assert_eq!(data.commitment.new_height, header.height().into());
                assert_eq!(data.commitment.new_state, None);
                assert!(!data.commitment.new_state_id.to_vec().is_empty());
                assert_eq!(
                    data.commitment.prev_height,
                    Some(new_ibc_height(1, 1).unwrap().into())
                );
                assert!(data.commitment.prev_state_id.is_some());
                assert_eq!(data.commitment.timestamp, header.timestamp().into());
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }

    #[test]
    fn test_verify_commitment() {
        let ctx = MockClientReader;
        let client = ParliaLightClient::default();
        let prefix = vec![0];
        let path = "commitments/ports/port-1/channels/channel-1/sequences/1";
        let proof_height = new_ibc_height(1, 2).unwrap();
        let client_id = ClientId::from_str("99-bscchain-0").unwrap();
        let mut expected = [0_u8; 32];
        expected[0] = 51;
        expected[1] = 52;
        let storage_proof_rlp = to_rlp(vec![
            hex!("f8918080a048477c6f9a27dd3b09ba3140d73536c56f2d038c2d1f0156450b5cdd75fec740808080a0044f9d4608bdd7ff7943cee62a73ac4daeff3c495907afd494dce25436b0c534a0dd774c97b7b9a5ff4ba0073aa76d58729ece6e20211ed97ef56b8baea52df394808080808080a0f8cf7dfa7a8c74ff54bf6717a6520081d72e7ec9076a9bacb263be17cf24cfdd8080").to_vec(),
            hex!("f843a030e8c8f21e1b1f55c0464131968b01fa0a534609e5ca17ab6d3dfae0fcbe0fcaa1a03334000000000000000000000000000000000000000000000000000000000000").to_vec()
        ]);

        match client.verify_membership(
            &ctx,
            client_id.clone(),
            prefix.clone(),
            path.to_string(),
            expected.to_vec(),
            proof_height.into(),
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => {
                assert_eq!(data.state_commitment.path, Path::from_str(path).unwrap());
                assert_eq!(data.state_commitment.height, proof_height.into());
                assert_eq!(data.state_commitment.value, Some(expected));
            }
            Err(e) => unreachable!("error {:?}", e),
        };

        let path = "commitments/ports/port-1/channels/channel-1/sequences/2";
        match client.verify_non_membership(
            &ctx,
            client_id,
            prefix,
            path.to_string(),
            proof_height.into(),
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => {
                assert_eq!(data.state_commitment.path, Path::from_str(path).unwrap());
                assert_eq!(data.state_commitment.height, proof_height.into());
                assert_eq!(data.state_commitment.value, None);
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }
}
