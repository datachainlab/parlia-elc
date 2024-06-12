use alloc::string::{String, ToString};
use alloc::vec::Vec;

use light_client::commitments::{
    EmittedState, MisbehaviourProxyMessage, PrevState, TrustingPeriodContext,
    UpdateStateProxyMessage, VerifyMembershipProxyMessage,
};
use light_client::{
    commitments::{gen_state_id_from_any, CommitmentPrefix, StateID, ValidationContext},
    types::{Any, ClientId, Height},
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient, MisbehaviourData,
    UpdateClientResult, UpdateStateData, VerifyMembershipResult, VerifyNonMembershipResult,
};
use patricia_merkle_trie::keccak::keccak_256;

use crate::client_state::ClientState;
use crate::commitment::{
    calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, verify_proof,
};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;

use crate::header::Header;
use crate::message::ClientMessage;
use crate::misbehaviour::Misbehaviour;

#[derive(Default)]
pub struct ParliaLightClient;

impl LightClient for ParliaLightClient {
    fn client_type(&self) -> String {
        "xx-parlia".to_string()
    }

    fn latest_height(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
    ) -> Result<Height, LightClientError> {
        let any_client_state = ctx.client_state(client_id)?;
        let client_state = ClientState::try_from(any_client_state)?;
        Ok(client_state.latest_height)
    }

    fn create_client(
        &self,
        _ctx: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, LightClientError> {
        let client_state = ClientState::try_from(any_client_state.clone())?;
        let consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let post_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        Ok(CreateClientResult {
            height,
            message: UpdateStateProxyMessage {
                prev_state_id: None,
                post_state_id,
                emitted_states: vec![EmittedState(height, any_client_state)],
                prev_height: None,
                post_height: height,
                timestamp,
                context: ValidationContext::Empty,
            }
            .into(),
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_message: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        match ClientMessage::try_from(any_message.clone())? {
            ClientMessage::Header(header) => Ok(self.update_state(ctx, client_id, header)?.into()),
            ClientMessage::Misbehaviour(misbehavior) => {
                let (client_state, prev_states, context) =
                    self.submit_misbehaviour(ctx, client_id, misbehavior)?;
                Ok(MisbehaviourData {
                    new_any_client_state: client_state.try_into()?,
                    message: MisbehaviourProxyMessage {
                        prev_states,
                        context,
                        client_message: any_message,
                    },
                }
                .into())
            }
        }
    }

    fn verify_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<VerifyMembershipResult, LightClientError> {
        let value = keccak_256(&value);
        let state_id = self.verify_commitment(
            ctx,
            client_id,
            &prefix,
            &path,
            Some(value.to_vec()),
            &proof_height,
            proof,
        )?;

        Ok(VerifyMembershipResult {
            message: VerifyMembershipProxyMessage::new(
                prefix,
                path,
                Some(value),
                proof_height,
                state_id,
            ),
        })
    }

    fn verify_non_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<VerifyNonMembershipResult, LightClientError> {
        let state_id =
            self.verify_commitment(ctx, client_id, &prefix, &path, None, &proof_height, proof)?;
        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipProxyMessage::new(prefix, path, None, proof_height, state_id),
        })
    }
}

impl ParliaLightClient {
    pub fn update_state(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        header: Header,
    ) -> Result<UpdateStateData, LightClientError> {
        //Ensure header can be verified.
        let height = header.height();
        let timestamp = header.timestamp()?;
        let trusted_height = header.trusted_height();
        let any_client_state = ctx.client_state(&client_id)?;
        let any_consensus_state = ctx.consensus_state(&client_id, &trusted_height)?;

        //Ensure client is not frozen
        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }

        // Create new state and ensure header is valid
        let trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let (new_client_state, new_consensus_state) = client_state.check_header_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state,
            header,
        )?;

        let trusted_state_timestamp = trusted_consensus_state.timestamp;
        let trusting_period = client_state.trusting_period;
        let max_clock_drift = client_state.max_clock_drift;
        let prev_state_id = gen_state_id(client_state, trusted_consensus_state)?;
        let post_state_id = gen_state_id(new_client_state.clone(), new_consensus_state.clone())?;

        Ok(UpdateStateData {
            new_any_client_state: new_client_state.try_into()?,
            new_any_consensus_state: new_consensus_state.try_into()?,
            height,
            message: UpdateStateProxyMessage {
                prev_state_id: Some(prev_state_id),
                post_state_id,
                emitted_states: Default::default(),
                prev_height: Some(trusted_height),
                post_height: height,
                timestamp,
                context: ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
                    trusting_period,
                    max_clock_drift,
                    timestamp,
                    trusted_state_timestamp,
                )),
            },
            prove: true,
        })
    }

    pub fn submit_misbehaviour(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        misbehaviour: Misbehaviour,
    ) -> Result<(ClientState, Vec<PrevState>, ValidationContext), LightClientError> {
        let any_client_state = ctx.client_state(&client_id)?;
        let any_consensus_state1 =
            ctx.consensus_state(&client_id, &misbehaviour.header_1.trusted_height())?;
        let any_consensus_state2 =
            ctx.consensus_state(&client_id, &misbehaviour.header_2.trusted_height())?;

        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }

        let trusted_consensus_state1 = ConsensusState::try_from(any_consensus_state1)?;
        let trusted_consensus_state2 = ConsensusState::try_from(any_consensus_state2)?;
        let new_client_state = client_state.check_misbehaviour_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state1,
            &trusted_consensus_state2,
            &misbehaviour,
        )?;

        let prev_state = self.make_prev_states(
            ctx,
            &client_id,
            &client_state,
            vec![
                misbehaviour.header_1.trusted_height(),
                misbehaviour.header_2.trusted_height(),
            ],
        )?;
        let context = ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
            client_state.trusting_period,
            client_state.max_clock_drift,
            misbehaviour.header_1.timestamp()?,
            trusted_consensus_state1.timestamp,
        ))
        .aggregate(ValidationContext::TrustingPeriod(
            TrustingPeriodContext::new(
                client_state.trusting_period,
                client_state.max_clock_drift,
                misbehaviour.header_2.timestamp()?,
                trusted_consensus_state2.timestamp,
            ),
        ))
        .map_err(Error::LCPCommitmentError)?;

        Ok((new_client_state, prev_state, context))
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_commitment(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        _prefix: &CommitmentPrefix,
        path: &str,
        value: Option<Vec<u8>>,
        proof_height: &Height,
        storage_proof_rlp: Vec<u8>,
    ) -> Result<StateID, LightClientError> {
        let client_state = ClientState::try_from(ctx.client_state(&client_id)?)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }
        let proof_height = *proof_height;
        if client_state.latest_height < proof_height {
            return Err(
                Error::UnexpectedProofHeight(proof_height, client_state.latest_height).into(),
            );
        }

        let consensus_state =
            ConsensusState::try_from(ctx.consensus_state(&client_id, &proof_height)?)?;
        let storage_root = consensus_state.state_root;
        let storage_proof = decode_eip1184_rlp_proof(&storage_proof_rlp)?;
        verify_proof(
            &storage_root,
            &storage_proof,
            calculate_ibc_commitment_storage_key(&client_state.ibc_commitments_slot, path)
                .as_slice(),
            &value,
        )?;

        gen_state_id(client_state, consensus_state)
    }

    fn make_prev_states(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
        client_state: &ClientState,
        heights: Vec<Height>,
    ) -> Result<Vec<PrevState>, LightClientError> {
        let mut prev_states = Vec::new();
        for height in heights {
            let consensus_state: ConsensusState =
                ctx.consensus_state(client_id, &height)?.try_into()?;
            prev_states.push(PrevState {
                height,
                state_id: gen_state_id(client_state.clone(), consensus_state)?,
            });
        }
        Ok(prev_states)
    }
}

fn gen_state_id(
    client_state: ClientState,
    consensus_state: ConsensusState,
) -> Result<StateID, LightClientError> {
    let client_state = Any::try_from(client_state.canonicalize())?;
    let consensus_state = Any::try_from(consensus_state.canonicalize())?;
    gen_state_id_from_any(&client_state, &consensus_state).map_err(LightClientError::commitment)
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;

    use alloc::vec::Vec;
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use light_client::types::{Any, ClientId, Height, Time};

    use light_client::commitments::{ProxyMessage, TrustingPeriodContext, ValidationContext};
    use light_client::{
        ClientReader, HostClientReader, HostContext, LightClient, UpdateClientResult,
        VerifyMembershipResult,
    };

    use patricia_merkle_trie::keccak::keccak_256;
    use rstest::rstest;
    use time::macros::datetime;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;

    use crate::fixture::{localnet, Network};
    use crate::header::Header;
    use crate::misbehaviour::Misbehaviour;
    use crate::misc::{new_height, Address, ChainId, Hash};
    use alloc::boxed::Box;

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: ChainId::new(9999),
                ibc_store_address: [0; 20],
                ibc_commitments_slot: hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
                trusting_period: core::time::Duration::new(86400 * 365 * 100, 0),
                max_clock_drift: core::time::Duration::new(1, 0),
                latest_height: Default::default(),
                frozen: false,
            }
        }
    }

    impl Default for ConsensusState {
        fn default() -> Self {
            ConsensusState {
                state_root: [0_u8; 32],
                timestamp: Time::from_unix_timestamp_nanos(
                    datetime!(2023-09-05 9:00 UTC).unix_timestamp_nanos() as u128,
                )
                .unwrap(),
                previous_validators_hash: [0_u8; 32],
                current_validators_hash: [0_u8; 32],
            }
        }
    }

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            Time::now()
        }
    }

    impl HostClientReader for MockClientReader {}

    impl store::KVStore for MockClientReader {
        fn set(&mut self, _key: Vec<u8>, _value: Vec<u8>) {
            todo!()
        }

        fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn remove(&mut self, _key: &[u8]) {
            todo!()
        }
    }

    impl ClientReader for MockClientReader {
        fn client_state(&self, client_id: &ClientId) -> Result<Any, light_client::Error> {
            let cs = self
                .client_state
                .clone()
                .ok_or_else(|| light_client::Error::client_state_not_found(client_id.clone()))?;
            Ok(Any::try_from(cs)?)
        }

        fn consensus_state(
            &self,
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let state = self
                .consensus_state
                .get(height)
                .ok_or_else(|| {
                    light_client::Error::consensus_state_not_found(client_id.clone(), *height)
                })?
                .clone();
            Ok(Any::try_from(state)?)
        }
    }

    fn mainnet() -> ChainId {
        ChainId::new(56)
    }

    #[test]
    fn test_success_create_client() {
        let client_state = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e745374617465124d08381214151f3951fa218cac426edfe078fa9e5c6dcea5001a2000000000000000000000000000000000000000000000000000000000000000002205109b9ea90f2a040880a305320410c0843d").to_vec();
        let consensus_state = hex!("0a2a2f6962632e6c69676874636c69656e74732e7061726c69612e76312e436f6e73656e7375735374617465126c0a2056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42110de82d5a8061a209c59cf0b5717cb6e2bd8620b7f3481605c8abcd45636bdf45c86db06338f0c5e22207a1dede35f5c835fecdc768324928cd0d9d9161e8529e1ba1e60451f3a9d088a").to_vec();
        let client = ParliaLightClient::default();
        let mock_consensus_state = BTreeMap::new();
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: mock_consensus_state,
        };
        let any_client_state: Any = client_state.try_into().unwrap();
        let any_consensus_state: Any = consensus_state.try_into().unwrap();
        let result = client
            .create_client(&ctx, any_client_state.clone(), any_consensus_state.clone())
            .unwrap();
        assert_eq!(result.height.revision_height(), 32132891);
        match result.message {
            ProxyMessage::UpdateState(data) => {
                assert_eq!(data.post_height, result.height);

                let cs = ConsensusState::try_from(any_consensus_state).unwrap();
                assert_eq!(data.timestamp.as_unix_timestamp_secs(), 1695891806);
                assert_eq!(
                    data.timestamp.as_unix_timestamp_secs(),
                    cs.timestamp.as_unix_timestamp_secs()
                );
                assert_eq!(data.emitted_states[0].0, result.height);
                assert_eq!(data.emitted_states[0].1, any_client_state);
                assert!(!data.post_state_id.to_vec().is_empty());
                assert!(data.prev_height.is_none());
                assert!(data.prev_state_id.is_none());
            }
            _ => unreachable!("invalid commitment"),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_update_state_neighboring_epoch(#[case] hp: Box<dyn Network>) {
        let input = hp.success_update_client_epoch_input();
        do_test_success_update_state(
            input.header,
            input.trusted_height,
            input.trusted_current_validators_hash,
            input.trusted_previous_validators_hash,
            input.new_current_validators_hash,
            input.new_previous_validators_hash,
            input.expected_storage_root,
            hp.ibc_store_address(),
            hp.network(),
        )
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_update_state_non_epoch(#[case] hp: Box<dyn Network>) {
        let input = hp.success_update_client_non_epoch_input();
        let new_current_validators_hash = input.trusted_current_validators_hash;
        let new_previous_validators_hash = input.trusted_previous_validators_hash;
        do_test_success_update_state(
            input.header,
            input.trusted_height,
            input.trusted_current_validators_hash,
            input.trusted_previous_validators_hash,
            new_current_validators_hash,
            new_previous_validators_hash,
            input.expected_storage_root,
            hp.ibc_store_address(),
            hp.network(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn do_test_success_update_state(
        header: Vec<u8>,
        trusted_height: u64,
        trusted_current_validator_hash: Hash,
        trusted_previous_validator_hash: Hash,
        new_current_validator_hash: Hash,
        new_previous_validator_hash: Hash,
        expected_storage_root: Hash,
        ibc_store_address: Address,
        chain_id: ChainId,
    ) {
        let any: Any = header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();
        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: trusted_current_validator_hash,
            previous_validators_hash: trusted_previous_validator_hash,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, trusted_height), trusted_cs.clone());
        let cs = ClientState {
            chain_id,
            ibc_store_address,
            latest_height: Height::new(0, trusted_height),
            ..Default::default()
        };
        let ctx = MockClientReader {
            client_state: Some(cs.clone()),
            consensus_state: mock_consensus_state,
        };
        match client.update_client(&ctx, client_id, any) {
            Ok(data) => {
                let data = match data {
                    UpdateClientResult::UpdateState(data) => data,
                    _ => unreachable!("invalid client result"),
                };
                let new_client_state = ClientState::try_from(data.new_any_client_state).unwrap();
                let new_consensus_state =
                    ConsensusState::try_from(data.new_any_consensus_state).unwrap();
                assert_eq!(data.height, header.height());
                assert_eq!(new_client_state.latest_height, header.height());
                assert_eq!(new_consensus_state.state_root, expected_storage_root);
                assert_eq!(new_consensus_state.timestamp, header.timestamp().unwrap());
                assert_eq!(
                    new_consensus_state.current_validators_hash,
                    new_current_validator_hash
                );
                assert_eq!(
                    new_consensus_state.previous_validators_hash,
                    new_previous_validator_hash
                );
                let data = data.message;
                assert_eq!(data.post_height, header.height());
                assert_eq!(data.emitted_states, vec![]);
                assert!(!data.post_state_id.to_vec().is_empty());
                assert_eq!(
                    data.prev_height,
                    Some(new_height(0, header.trusted_height().revision_height()))
                );
                assert!(data.prev_state_id.is_some());
                assert_eq!(data.timestamp, header.timestamp().unwrap());
                match &data.context {
                    ValidationContext::TrustingPeriod(actual) => {
                        let expected = TrustingPeriodContext::new(
                            cs.trusting_period,
                            cs.max_clock_drift,
                            header.timestamp().unwrap(),
                            trusted_cs.timestamp,
                        );
                        assert_eq!(format!("{}", actual), format!("{}", expected));
                    }
                    _ => unreachable!("invalid commitment context {:?}", data.context),
                }
            }
            err => unreachable!("err {:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_update_state(#[case] hp: Box<dyn Network>) {
        let input = hp.error_update_client_input();
        let header = input.header;
        let any: Any = header.try_into().unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: input.trusted_current_validators_hash,
            previous_validators_hash: input.trusted_previous_validators_hash,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, input.trusted_height), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: hp.network(),
                ibc_store_address: hp.ibc_store_address(),
                latest_height: Height::new(0, input.trusted_height),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        // fail: check_header_and_update_state
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "UnexpectedPreviousValidatorsHash");

        // assert fixture validity
        let de_header: Header = any.clone().try_into().unwrap();
        assert_ne!(
            de_header.eth_header().target.hash,
            de_header.eth_header().all[1].parent_hash.as_slice()
        );

        // fail: client_frozen
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                frozen: true,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "ClientFrozen: xx-parlia-1");

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: mock_consensus_state,
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "client_state not found: client_id=xx-parlia-1");

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: hp.network(),
                ibc_store_address: hp.ibc_store_address(),
                latest_height: Height::new(0, input.trusted_height),
                ..Default::default()
            }),
            consensus_state: BTreeMap::new(),
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert_err(
            err,
            &format!(
                "consensus_state not found: client_id=xx-parlia-1 height=0-{}",
                input.trusted_height
            ),
        );
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_update_state_non_neighboring_epoch(#[case] hp: Box<dyn Network>) {
        let input = hp.error_update_client_non_neighboring_epoch_input();
        let header = input.0;
        let trusted_height = input.1;

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(Height::new(0, trusted_height), ConsensusState::default());
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: mock_consensus_state,
        };
        let err = client
            .update_client(&ctx, client_id, header.try_into().unwrap())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains(&format!("UnexpectedTrustedHeight: {trusted_height}")),
            "{}",
            err
        );
    }

    #[test]
    fn test_success_verify_membership() {
        let proof_height = new_height(0, 232);
        let proof = hex!("f902ccf90211a06868e3a43071c06084145e2546b14ab7b49b4a073213228fd2fe5b9ad6978723a032238795ce6d015be83c499b744c7108308321b5c52b424bdfe851819470572ca0db54777eae7ba641adeb842ebae3b86206443a817af6211162cb7b8f54685722a094b114ebfe63288bd344dc06b50a25982f93b38ae7deb1c4f0085a80b76692fda087385f44c834ce1d100176adb7dabf314d3d3799e83cecbdbae8bf0047bbeb8da0afa75930fdc8b5bbcc7de9653a126bbd5e7480ba180117ac8f6448ac620fe881a0c9970b5bcfc0a37c601a907ab40e0d73fe4a19b00564ebfaa2962bc4659937e8a07c6b19783013eefd4b7362ea987dda4509b7a6f6b9fa765f4be79817023c9fefa0c928ae51650933cbdc43721f48a8d96b1ff49326b6afc59fe4441a6ab4ec6391a0c60665890ed3028fb4cc13ffe5b37f9eaf93886aa0920ea7aab00e5f36a58cb9a0341de64564e1cde279f15a152a41fc07b955ed8fb331e8fbb70b6ada2f4533c1a0eb2cfd02210dd040808b05b9fcb94d99fb459a04cbaae816a87b30224962b82fa0dbd758e0c3164e578837b817584efafc5582fa3ad872bc59ba20a0ff29d84438a0ad31c527b35a0c5a0f50c15bcba55b473de5ced9ab8c22736bc71ca7ff5f9e4fa03d448120e46b82861ae5eccd3a72e3c12f8cd350b466dc27586a1d6d58791212a08a70cfd0b8005d9c457f0d83b1a7b29244963fadf71fb1ce35764fe7141bc90080f8718080808080a0ce42aec576e424376d1bfec5089611170bedc488327075ec1c37905b2eb04a7b80808080a0e8c783a5d1417b9c3c59e642b630d1fb818a3ca870068c33a8d3b3114d1a31278080a05868dd463ca96a009a6bbf76fe9a9d904ca04e30b83a3759619f191367ce5b26808080f843a0203fc42ddf6c1b5bb218ce24e14c40af9e0eb127a5d76050d37d7369e2fc4a47a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("4050c398b206f467b6d88cfd3d877a11f65701c37aabaa48d77466a63dfda9b7");
        let value = hex!("0a0b78782d7061726c69612d3012230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180322220a0b78782d7061726c69612d30120c636f6e6e656374696f6e2d301a050a03696263").to_vec();
        let path = "connections/connection-0";
        let result = do_test_verify_membership(
            path,
            value.to_vec(),
            proof_height,
            proof.to_vec(),
            state_root,
            proof_height,
            false,
        )
        .unwrap();
        let data = result.message;
        assert_eq!(data.path, path);
        assert_eq!(data.height, proof_height);
        assert_eq!(data.value, Some(keccak_256(value.as_slice())));
    }

    #[test]
    fn test_error_verify_membership() {
        let proof_height = new_height(0, 232);
        let proof = hex!("f902ccf90211a06868e3a43071c06084145e2546b14ab7b49b4a073213228fd2fe5b9ad6978723a032238795ce6d015be83c499b744c7108308321b5c52b424bdfe851819470572ca0db54777eae7ba641adeb842ebae3b86206443a817af6211162cb7b8f54685722a094b114ebfe63288bd344dc06b50a25982f93b38ae7deb1c4f0085a80b76692fda087385f44c834ce1d100176adb7dabf314d3d3799e83cecbdbae8bf0047bbeb8da0afa75930fdc8b5bbcc7de9653a126bbd5e7480ba180117ac8f6448ac620fe881a0c9970b5bcfc0a37c601a907ab40e0d73fe4a19b00564ebfaa2962bc4659937e8a07c6b19783013eefd4b7362ea987dda4509b7a6f6b9fa765f4be79817023c9fefa0c928ae51650933cbdc43721f48a8d96b1ff49326b6afc59fe4441a6ab4ec6391a0c60665890ed3028fb4cc13ffe5b37f9eaf93886aa0920ea7aab00e5f36a58cb9a0341de64564e1cde279f15a152a41fc07b955ed8fb331e8fbb70b6ada2f4533c1a0eb2cfd02210dd040808b05b9fcb94d99fb459a04cbaae816a87b30224962b82fa0dbd758e0c3164e578837b817584efafc5582fa3ad872bc59ba20a0ff29d84438a0ad31c527b35a0c5a0f50c15bcba55b473de5ced9ab8c22736bc71ca7ff5f9e4fa03d448120e46b82861ae5eccd3a72e3c12f8cd350b466dc27586a1d6d58791212a08a70cfd0b8005d9c457f0d83b1a7b29244963fadf71fb1ce35764fe7141bc90080f8718080808080a0ce42aec576e424376d1bfec5089611170bedc488327075ec1c37905b2eb04a7b80808080a0e8c783a5d1417b9c3c59e642b630d1fb818a3ca870068c33a8d3b3114d1a31278080a05868dd463ca96a009a6bbf76fe9a9d904ca04e30b83a3759619f191367ce5b26808080f843a0203fc42ddf6c1b5bb218ce24e14c40af9e0eb127a5d76050d37d7369e2fc4a47a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("4050c398b206f467b6d88cfd3d877a11f65701c37aabaa48d77466a63dfda9b7");
        let value = hex!("0a0b78782d7061726c69612d3012230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180322220a0b78782d7061726c69612d30120c636f6e6e656374696f6e2d301a050a03696263").to_vec();
        let path = "connections/connection-0";

        let err = do_test_verify_membership(
            path,
            value[0..1].to_vec(),
            proof_height,
            proof.to_vec(),
            state_root,
            proof_height,
            false,
        )
        .unwrap_err();
        assert_err(err, "UnexpectedStateValue");

        let latest_height = new_height(
            proof_height.revision_number(),
            proof_height.revision_height() - 1,
        );
        let err = do_test_verify_membership(
            path,
            value.clone(),
            proof_height,
            proof.to_vec(),
            state_root,
            latest_height,
            false,
        )
        .unwrap_err();
        assert_err(err, "UnexpectedProofHeight");

        let err = do_test_verify_membership(
            path,
            value,
            proof_height,
            proof.to_vec(),
            state_root,
            latest_height,
            true,
        )
        .unwrap_err();
        assert_err(err, "ClientFrozen: xx-parlia-0");
    }

    fn do_test_verify_membership(
        path: &str,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
        state_root: Hash,
        latest_height: Height,
        frozen: bool,
    ) -> Result<VerifyMembershipResult, light_client::Error> {
        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 0).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            proof_height,
            ConsensusState {
                state_root,
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height,
                frozen,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        client.verify_membership(
            &ctx,
            client_id,
            "ibc".into(),
            path.to_string(),
            value,
            proof_height,
            proof,
        )
    }

    #[test]
    fn test_success_submit_misbehavior() {
        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // Detect misbehavior
        // Use blocks of two local nets with the same ChainID(=9999) and validator set.
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212b1340a0b78782d7061726c69612d31128f1a0a90060a8d06f9030aa025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b150a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a58402625a00808465122d33b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608ce4e95f382e2d06eb6c98641c574069f7c8cfdb482a4c58290f9f2ee86f6d4ce520d7bb6a6be1acd082c07a9d65b45f1334def3c66fc793003cf06f3fcea7ce055b34aa911f6ff7b9bf2eb083f3e7010a34e8c61aa70edd8ad630c82f3d4a8bf8488204a3a02d59fc7d664ae17504839bf6c49ca0e21fa794fe661c86e929a522bd4872d3458204a4a025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b1508022216e66d52050e392e6a6b86f677363e01be8deb6611cab76cada1bfd6c0b7048798c2376f52d8357d8aeb6e6c0109dd802675c849dff145dc3dd470fc7bce400a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a68402625a00808465122d36b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608f21cd736cba2bf8c4af32f237f4851282c77b602f3e5ef48c48e16b36fae2f8a80bdb501d48c235b3409ec53340742919fbab1a54cde9da53886da4e7280a7c450714fbdd1dd5907a9f4990fb99e1badebba671d521d47f1cdd23ce3eec2e90f8488204a4a025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b1508204a5a09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508804b8debfb8d55a7f71547fd88e1c40eb0efe960d32d08601589e22a62bb0ebeb26b984bba8f736484ae789567e5d9563104126e78181a293d6ee504e9ad35725801a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa086efaa0d95f31de170d88687b07806f3bf271bf842b65f6dd76b326e1575e609a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a78402625a00808465122d39b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b86094c8bc4a6ed9b43a592f7c7a035e27b119ff45ea9e7e6ab149136ab18f268499c6d6d920aab86608315093fffaa354cf0077173664aebe97ca185285e739559a01c96d04a30df92c23ce051b1700c8fabd41e1ac8db8229a3c08a067a60a4ee7f8488204a5a09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac215088204a6a086efaa0d95f31de170d88687b07806f3bf271bf842b65f6dd76b326e1575e6098085641457482587c8687b5e40069f915f48961cad6069305c278fb117d4661cd80c92987afd0b4e44e794945580feeedece4b1b68098b6134de8be2ed2245aa8b01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310a0091aaa04f90227f901d1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a0c445c1e18313a154c9cfd1a1bdbf2fb6d7513227c59c5cfe4ed6b2f1585ea74ea06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a562a0726016a81a8017e5825a30ad9481c2ea45a35601f9e17a25ef74fb2fcc093ecb80a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a075d1dffd2abda435b74cfaccf176f5e0938c60d66068a44727add2ef2df1f3eea0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a04f3e6cb5f42f4cfe12e8e586e820edf8460ca87b27b4823c129d986c127e4898a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a054529b9b4e918ca60d7d2c1f1c9104a1442f9dcee09012b637ec7bd7ec46702680f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca8080808022448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff2a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff1a8f1a0a90060a8d06f9030aa0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d04a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a58402625a00808465122d36b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b860a0be31d422b4b017cc814dedd756cafcaff3c871779a6321284cebe91e5e1c2c0cb49b65be2a9bb41eabfc5480c8c75f0906339f62235d0b4352b3af1e38c79986cc1eb16880f26dd9c8f40bd8020890985d59f01bba4dd46df62be6a0c05414f8488204a3a0263c6cea09d25bb460401680cc3142f116c5a377f8ef11060e80f0f612f1c3168204a4a0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d0480f7464a0e50746e1283e82b6ea17ec53c71c61ed86665a300756b53d37dd3991346774d2ac3c242d8f0371f0ebe08f5af80757c6cd3e239212106d05d067064a300a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f74269a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a68402625a00808465122d39b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608ae8e9f3eeb44fc2ace50cb82e7922ccfad7571f507e89282474c970cd87f2f90cb7e3e22ef872e48cc904015c4792290b172b0e9aef2090a9ee653c0f258c215314c810b42b1a4399378cfeb7e8130082d7048bbc25c56373e4167b25feb51ff8488204a4a0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d048204a5a04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f742698048e891fd5b3f1eed759866fe722882c746dab531d47e972732640e42f49365b1348eb77bdc7425486f16a59b5080dd87b9406f1d532c37b8589e4b666cfd855b00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa0ccdadba9c31c3462045f7552ec31591fc033d53cc02f66efe74a7a11527dd886a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a78402625a00808465122d3cb90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b860b5564a5fdce667a739c336d6b07beec17f8afcbc72da74f98e690327c32893b81ff51a6badcb7dfc0af7de042dc3b90e0467fef125d666956f3179b5330fc7a47624858eee5cb9edc93b45677417b742d213d97205770fcd0a36d6c409f551aff8488204a5a04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f742698204a6a0ccdadba9c31c3462045f7552ec31591fc033d53cc02f66efe74a7a11527dd88680299e2c8ee9446f79b09078581adec0382f5f0a5f49986493802bc10349e535d71b7e2d734818374617361443398ac0a3e3a343b7ca920586db67a7dcae60018101a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310a0091aaa04f90227f901d1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a010790f90204b51f76a67de8b4bd23f62ea75f921641ff583a3ec5e8d681df975a06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a562a051b92742fd280c4a2285b18197d40134dfe7d903b7d707cea1bd5f442a78a63580a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a022a617263a20b5549555a9424a99ea156c9337b4b2009f9274febe93638918aaa0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a04f3e6cb5f42f4cfe12e8e586e820edf8460ca87b27b4823c129d986c127e4898a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a09ab965be5ca3cbb09432f80709f918076cbad663afd466131fd184c8bda104c480f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca8080808022448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff2a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff").to_vec();
        let any: Any = any.try_into().unwrap();
        let misbehavior = Misbehaviour::try_from(any.clone()).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: misbehavior.header_1.current_epoch_validators_hash(),
            previous_validators_hash: misbehavior.header_1.previous_epoch_validators_hash(),
            ..Default::default()
        };
        mock_consensus_state.insert(misbehavior.header_1.trusted_height(), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: mock_consensus_state,
        };

        let result = client.update_client(&ctx, client_id.clone(), any);
        match result {
            Ok(UpdateClientResult::Misbehaviour(mdt)) => {
                let expected_cs: ClientState = mdt.new_any_client_state.try_into().unwrap();
                let prev_state = mdt.message.prev_states;
                let context = mdt.message.context;
                assert!(expected_cs.frozen);
                assert_eq!(prev_state.len(), 2);
                assert_eq!(prev_state[0].height, misbehavior.header_1.trusted_height());
                assert_eq!(prev_state[1].height, misbehavior.header_2.trusted_height());
                if let ValidationContext::Empty = context {
                    unreachable!("invalid validation context");
                }
            }
            other => unreachable!("err={:?}", other),
        };

        // assert fixture validity
        assert_eq!(misbehavior.client_id, client_id);
        assert_eq!(misbehavior.header_1.height(), new_height(0, 1189));
        assert_eq!(
            misbehavior.header_1.block_hash(),
            &hex!("9432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508")
        );
        assert_eq!(misbehavior.header_2.height(), misbehavior.header_1.height());
        assert_eq!(
            misbehavior.header_2.trusted_height(),
            misbehavior.header_1.trusted_height()
        );
        assert_ne!(
            misbehavior.header_2.block_hash(),
            misbehavior.header_1.block_hash()
        );
    }

    #[test]
    fn test_error_submit_misbehavior() {
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // fail: exactly same block
        let mut any= hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212898e010a0b78782d7061726c69612d3112fb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd075").to_vec();
        let any2= hex!("6e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd01afb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehavior
        let err = client
            .update_client(&ctx, client_id.clone(), any)
            .unwrap_err();
        assert_err(err, "UnexpectedSameBlockHash : 0-32160267");

        // fail: invalid block
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: hex!(
                "abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac"
            ),
            previous_validators_hash: hex!(
                "dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71"
            ),
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 32160266), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: mainnet(),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        let mut any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212898e010a0b78782d7061726c69612d3112fb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd075").to_vec();
        let any2 = hex!("6e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd01afb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa00000000000000000000000000000000000000000000000000000000000000000a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehavior
        let _ = Misbehaviour::try_from(any.clone()).unwrap();
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "UnexpectedHeaderRelation: 32160267 32160268");

        // fail: client state is frozen
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                frozen: true,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "ClientFrozen: xx-parlia-1");

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "consensus_state not found: client_id=xx-parlia-1");

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: BTreeMap::new(),
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert_err(err, "client_state not found");
    }

    fn assert_err(err: light_client::Error, contains: &str) {
        assert!(format!("{:?}", err).contains(contains), "{}", err);
    }
}
