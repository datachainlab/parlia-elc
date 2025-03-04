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
use crate::errors::{ClientError, Error};
use crate::fork_spec::HeightOrTimestamp;
use crate::header::hardfork::{MINIMUM_HEIGHT_SUPPORTED, MINIMUM_TIMESTAMP_SUPPORTED};
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
        let client_state =
            ClientState::try_from(any_client_state).map_err(|e| ClientError::LatestHeight {
                cause: e,
                client_id: client_id.clone(),
            })?;
        Ok(client_state.latest_height)
    }

    fn create_client(
        &self,
        ctx: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, LightClientError> {
        InnerLightClient
            .create_client(ctx, any_client_state.clone(), any_consensus_state.clone())
            .map_err(|e| {
                ClientError::CreateClient {
                    cause: e,
                    client_state: any_client_state,
                    consensus_sate: any_consensus_state,
                }
                .into()
            })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_message: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        InnerLightClient
            .update_client(ctx, client_id.clone(), any_message.clone())
            .map_err(|e| {
                ClientError::UpdateClient {
                    cause: e,
                    client_id,
                    message: any_message,
                }
                .into()
            })
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
        InnerLightClient
            .verify_membership(
                ctx,
                client_id.clone(),
                prefix.clone(),
                path.clone(),
                value.clone(),
                proof_height,
                proof.clone(),
            )
            .map_err(|e| {
                ClientError::VerifyMembership {
                    cause: e,
                    client_id,
                    prefix,
                    path,
                    value,
                    proof_height,
                    proof,
                }
                .into()
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
        InnerLightClient
            .verify_non_membership(
                ctx,
                client_id.clone(),
                prefix.clone(),
                path.clone(),
                proof_height,
                proof.clone(),
            )
            .map_err(|e| {
                ClientError::VerifyNonMembership {
                    cause: e,
                    client_id,
                    prefix,
                    path,
                    proof_height,
                    proof,
                }
                .into()
            })
    }
}

struct InnerLightClient;

impl InnerLightClient {
    fn create_client(
        &self,
        _ctx: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, Error> {
        let client_state = ClientState::try_from(any_client_state.clone())?;
        let consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let post_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        #[allow(clippy::absurd_extreme_comparisons)]
        if timestamp.as_unix_timestamp_secs() < MINIMUM_TIMESTAMP_SUPPORTED {
            return Err(Error::UnsupportedMinimumTimestamp(timestamp));
        }
        #[allow(clippy::absurd_extreme_comparisons)]
        if height.revision_height() < MINIMUM_HEIGHT_SUPPORTED {
            return Err(Error::UnsupportedMinimumHeight(height));
        }
        if height.revision_height() == 0 {
            return Err(Error::UnexpectedRevisionHeight(height.revision_height()));
        }

        if client_state.fork_specs.is_empty() {
            return Err(Error::EmptyForkSpec);
        }
        for spec in &client_state.fork_specs {
            match spec.height_or_timestamp {
                HeightOrTimestamp::Height(height) =>
                {
                    #[allow(clippy::absurd_extreme_comparisons)]
                    if height < MINIMUM_HEIGHT_SUPPORTED {
                        return Err(Error::UnsupportedMinimumHeightForkSpec(height));
                    }
                }
                HeightOrTimestamp::Time(time) =>
                {
                    #[allow(clippy::absurd_extreme_comparisons)]
                    if time < MINIMUM_TIMESTAMP_SUPPORTED {
                        return Err(Error::UnsupportedMinimumTimestampForkSpec(time));
                    }
                }
            }
        }

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
    ) -> Result<UpdateClientResult, Error> {
        match ClientMessage::try_from(any_message.clone())? {
            ClientMessage::Header(header) => Ok(self.update_state(ctx, client_id, header)?.into()),
            ClientMessage::Misbehaviour(misbehaviour) => {
                let (client_state, prev_states, context) =
                    self.submit_misbehaviour(ctx, client_id, misbehaviour)?;
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

    #[allow(clippy::too_many_arguments)]
    fn verify_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<VerifyMembershipResult, Error> {
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
    ) -> Result<VerifyNonMembershipResult, Error> {
        let state_id =
            self.verify_commitment(ctx, client_id, &prefix, &path, None, &proof_height, proof)?;
        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipProxyMessage::new(prefix, path, None, proof_height, state_id),
        })
    }

    pub fn update_state(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        header: Header,
    ) -> Result<UpdateStateData, Error> {
        //Ensure header can be verified.
        let height = header.height();
        let timestamp = header.timestamp()?;
        let trusted_height = header.trusted_height();
        let any_client_state = ctx.client_state(&client_id).map_err(Error::LCPError)?;
        let any_consensus_state = ctx
            .consensus_state(&client_id, &trusted_height)
            .map_err(Error::LCPError)?;

        //Ensure client is not frozen
        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id));
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
    ) -> Result<(ClientState, Vec<PrevState>, ValidationContext), Error> {
        let any_client_state = ctx.client_state(&client_id).map_err(Error::LCPError)?;
        let any_consensus_state1 = ctx
            .consensus_state(&client_id, &misbehaviour.header_1.trusted_height())
            .map_err(Error::LCPError)?;
        let any_consensus_state2 = ctx
            .consensus_state(&client_id, &misbehaviour.header_2.trusted_height())
            .map_err(Error::LCPError)?;

        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id));
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
    ) -> Result<StateID, Error> {
        let client_state =
            ClientState::try_from(ctx.client_state(&client_id).map_err(Error::LCPError)?)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id));
        }
        let proof_height = *proof_height;
        if client_state.latest_height < proof_height {
            return Err(Error::UnexpectedProofHeight(
                proof_height,
                client_state.latest_height,
            ));
        }

        let consensus_state = ConsensusState::try_from(
            ctx.consensus_state(&client_id, &proof_height)
                .map_err(Error::LCPError)?,
        )?;
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
    ) -> Result<Vec<PrevState>, Error> {
        let mut prev_states = Vec::new();
        for height in heights {
            let consensus_state: ConsensusState = ctx
                .consensus_state(client_id, &height)
                .map_err(Error::LCPError)?
                .try_into()?;
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
) -> Result<StateID, Error> {
    let client_state = Any::try_from(client_state.canonicalize())?;
    let consensus_state = Any::try_from(consensus_state.canonicalize())?;
    gen_state_id_from_any(&client_state, &consensus_state)
        .map_err(LightClientError::commitment)
        .map_err(Error::LCPError)
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

    use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
    use crate::misbehaviour::Misbehaviour;
    use crate::misc::{new_height, Address, ChainId, Hash};
    use alloc::boxed::Box;

    fn after_pascal() -> ForkSpec {
        ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(0),
            additional_header_item_count: 1, // requestsHash
        }
    }

    fn before_pascal() -> ForkSpec {
        ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(0),
            additional_header_item_count: 0, // requestsHash
        }
    }

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
                fork_specs: vec![after_pascal()],
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
            Ok(Any::try_from(cs).unwrap())
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
            Ok(Any::try_from(state).unwrap())
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_create_client(#[case] hp: Box<dyn Network>) {
        let (client_state , consensus_state, height, timestamp) = hp.success_create_client();
        let client = ParliaLightClient;
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
        assert_eq!(result.height.revision_height(), height);
        match result.message {
            ProxyMessage::UpdateState(data) => {
                assert_eq!(data.post_height, result.height);

                let cs = ConsensusState::try_from(any_consensus_state).unwrap();
                assert_eq!(data.timestamp.as_unix_timestamp_secs(), timestamp);
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
    fn test_error_create_client(#[case] hp: Box<dyn Network>) {
        let runner = |func: Box<dyn FnOnce(ClientState) -> ClientState>| {
            let (client_state , consensus_state, _, _) = hp.success_create_client();
            let client = ParliaLightClient;
            let mock_consensus_state = BTreeMap::new();
            let ctx = MockClientReader {
                client_state: None,
                consensus_state: mock_consensus_state,
            };
            let mut any_client_state: Any = client_state.try_into().unwrap();
            let mut client_state = ClientState::try_from(any_client_state.clone()).unwrap();
            client_state = func(client_state);
            let any_client_state: Any = client_state.try_into().unwrap();
            let any_consensus_state: Any = consensus_state.try_into().unwrap();
            client
                .create_client(&ctx, any_client_state.clone(), any_consensus_state.clone())
                .unwrap_err()
        };

        let result = runner(Box::new(|mut client_state| {
            client_state.latest_height = Height::new(0, 0);
            client_state
        }));
        assert_err(result, "UnexpectedRevisionHeight");

        let result = runner(Box::new(|mut client_state| {
            client_state.fork_specs = vec![];
            client_state
        }));
        assert_err(result, "EmptyForkSpec");
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
        let client = ParliaLightClient;
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
    fn test_success_update_state_continuous(#[case] hp: Box<dyn Network>) {
        let client = ParliaLightClient;
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let header_groups = hp.success_update_client_continuous_input();

        for headers in header_groups {
            let any: Any = headers.first().unwrap().clone().try_into().unwrap();
            let first = Header::try_from(any.clone()).unwrap();
            if !first.eth_header().target.is_epoch() {
                panic!("first header of each group must be epoch");
            }
            // create client
            let mut mock_consensus_state = BTreeMap::new();
            let trusted_cs = ConsensusState {
                current_validators_hash: first.previous_epoch_validators_hash(),
                ..Default::default()
            };
            mock_consensus_state.insert(first.trusted_height(), trusted_cs.clone());
            let mut cs = ClientState {
                chain_id: hp.network(),
                ibc_store_address: hp.ibc_store_address(),
                latest_height: first.trusted_height(),
                ..Default::default()
            };

            let mut ctx = MockClientReader {
                client_state: Some(cs.clone()),
                consensus_state: mock_consensus_state,
            };
            for header in &headers {
                let any: Any = header.clone().try_into().unwrap();
                let header = Header::try_from(any.clone()).unwrap();
                let result = client.update_client(&ctx, client_id.clone(), any).unwrap();
                match result {
                    UpdateClientResult::UpdateState(state) => {
                        ctx.consensus_state.insert(
                            header.height(),
                            state.new_any_consensus_state.try_into().unwrap(),
                        );
                        cs.latest_height = state.height;
                    }
                    _ => unreachable!("invalid update_client result"),
                }
            }

            let any: Any = headers.last().unwrap().clone().try_into().unwrap();
            let last = Header::try_from(any.clone()).unwrap();
            assert_eq!(cs.latest_height, last.height());
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_update_state(#[case] hp: Box<dyn Network>) {
        let input = hp.success_update_client_epoch_input();
        let header = input.header;
        let any: Any = header.try_into().unwrap();

        let client = ParliaLightClient;
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();

        // fail: check_header_and_update_state (invalid validator hash)
        mock_consensus_state.insert(
            Height::new(0, input.trusted_height),
            ConsensusState {
                current_validators_hash: [0u8; 32],
                previous_validators_hash: input.trusted_previous_validators_hash,
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: hp.network(),
                ibc_store_address: hp.ibc_store_address(),
                latest_height: Height::new(0, input.trusted_height),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "UnexpectedUntrustedValidatorsHashInEpoch");

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
        let input = Any::try_from(hp.error_update_client_non_neighboring_epoch_input()).unwrap();
        let header = Header::try_from(input.clone()).unwrap();
        let trusted_height = header.trusted_height();

        let client = ParliaLightClient;
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(trusted_height, ConsensusState::default());
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: mock_consensus_state,
        };
        let err = client.update_client(&ctx, client_id, input).unwrap_err();
        assert_err(
            err,
            &format!(
                "UnexpectedTrustedHeight: {}",
                trusted_height.revision_height()
            ),
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
        let expected = format!("{:?}", err).contains("ClientFrozen: xx-parlia-0");
        assert!(expected, "{}", err);
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
        let client = ParliaLightClient;
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
    fn test_success_submit_misbehaviour() {
        let client = ParliaLightClient;
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // Detect misbehaviour
        // Use blocks of two local nets with the same ChainID(=9999) and validator set.
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212ad3b0a0b78782d7061726c69612d3112c11c0ad5060ad206f9034fa0df813ab13cd8fa64526bab2d574bd83199f358cf875b5a7ca34c55cc59fb7841a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0347db7085bed92889205f4566fdeb71b36981b2662282e5b49f74f146e1b2920a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022d8402625a00808466a21174b90111d98301040c846765746889676f312e32312e3132856c696e7578000060b2e37bf8ae03b860b42b097ae5430552430062d80b2015710882c0520cf58dc6b987d0aa042840525bab13a5098af712b844bccf36b2ccb009fa3796f7088dec9a5dfcc0db6e4ab502fcca21d59598bd4f7504415662ec094b6ba1555c7faa0389468e45e11e8655f84882022ba0fe631870634a3823f363cdb9c6bd572b1a3ecaa9daeb98a784610a1cd1107e4882022ca0df813ab13cd8fa64526bab2d574bd83199f358cf875b5a7ca34c55cc59fb78418008487b8053f33e79d8758655252a23e25ce9f3440557d0ed67c80700633730674c5c682fa86414f136befd54de6023cbbb74bc48edc438ad136bc34f520b264100a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa09e0419600f424df6786dbbdef3f774c0a3d9a9785c8e3aec85ec4d95a2a526ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0347db7085bed92889205f4566fdeb71b36981b2662282e5b49f74f146e1b2920a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022e8402625a00808466a21177b90111d98301040c846765746889676f312e32312e3132856c696e7578000060b2e37bf8ae03b86099480987f69ba68b91ea25863b7cc7881fa57156c57f04b9a1ce33fa6766522d1ddafbb4b0ebd913bedee575cf18790f163d68c5d8fc5d389206ec1baf04b7daf1b17c9b5e688f29e71bfc5c40c5327dd6a36a7fd6e043305f6fe01da6fc77bff84882022ca0df813ab13cd8fa64526bab2d574bd83199f358cf875b5a7ca34c55cc59fb784182022da09e0419600f424df6786dbbdef3f774c0a3d9a9785c8e3aec85ec4d95a2a526ad80aab31b654039b4edef9af34f1bfbff4999aafd9c007bb3925378e865a8fde7d9693646834fc0323d375029594e363a4d96d49d0d5bc1dd6d98ed87d13fcfc4a700a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa0d71391dfe369c3f939c86aa6c3a25649a5ce9c298549e075981d65dc3278fadda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0347db7085bed92889205f4566fdeb71b36981b2662282e5b49f74f146e1b2920a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022f8402625a00808466a2117ab90111d98301040c846765746889676f312e32312e3132856c696e7578000060b2e37bf8ae03b860acd5509943efb944b23870db31f09b536731993d75078450bedefa5df77ea416d2d54be798d452d4562b57571fcf3ec00596cb4516d86b82a52081275c9ff9a35aed899b63791acbff7000f3c907c9d9f61e386c8c0de5ea79d67fd49c5675abf84882022da09e0419600f424df6786dbbdef3f774c0a3d9a9785c8e3aec85ec4d95a2a526ad82022ea0d71391dfe369c3f939c86aa6c3a25649a5ce9c298549e075981d65dc3278fadd8076a78528fffc86138b8155eaf036c0ccced82091d1cd7be5e7445d9d44b512907766334023ba1ac6b5376b39619e7198467598e549b284dcd065b4088ee0be0600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000120310ac041a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0cb21354718f7d012561dacf2274405cdd9bccd532afe18206bd26bf60e96c853a0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a09e8d71308bd38616ac52a39498cee9fcf29c440d9aacfedfc7143772c77ce54480a0a74e307420bf9966d5db9a83ce48edc32c7a8e43328c6373de6875cefa04ad7aa004371241b9d6f35e1f361f2109d19a9192a9c0c749b2bd15fcb131a1a6ce5e3ba00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0d4182165b298d7b52b0f2064d19ab8bdad2b3955fa5b3d85c00673beb97e124480f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a03f47312ca98ac1f6ae9db9752c2a33529723b64e654d87f7847cee0382edfb55a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e56592b50b17b5348f1aebe4c50d87c59b55223abe57c9c3df76cb4a96211bb393aacd440bac5f71ea3fc481abff6270142d2244a7876ea32e7a748c697d01345145485561305b24aed19f6cbeb659e104b4657c2e41822087506cb58b037aba5599314c2c4bea0ef4d3cbbc449b24abf396cfd71ac07af42a448fdaaa7e6631e438625ca25c857a3727ea28e56592b50b17b5348f1aebe4c50d87c59b55223abe57c9c3df76cb4a96211bb393aacd440bac5f71ea3fc481abff6270142d2a44d9a13701eafb76870cb220843b8c6476824bfa1595bd9f541fdb277d2bdd5ff223f95eb83f8d2b465c1bac3cf2d0bc551ad01a9037a4af083d66eff89b34200745db92cc300538061ad91e0ad5060ad206f9034fa0aeef6b8a15e0109c9838875b033b5c54d21c356cb5ddf395eb109b9b29ae694fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03e5bfca057d64cd5c54c82f5e213f8e7993411a5a490c0b93358f6def507e8d4a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022d8402625a00808466a2116eb90111d98301040c846765746889676f312e32312e3132856c696e75780000e0299c2ff8ae0fb86082b910df7cee75733375fb7716c34b14c1ce27f283c2d87ea0e2b2a0de42d18bdd724766b3a73d5daaa25befaa814df815605e8881819d421c8703100b7a93d1a22c89693625b4370d4d87b85ed676661ce65d46ef0c5c8325696892abf0d5d5f84882022ba03986751eb813b176c13e29485332e635df862b515516501e87113f50b655d80c82022ca0aeef6b8a15e0109c9838875b033b5c54d21c356cb5ddf395eb109b9b29ae694f80af43c5cc71b487cbe16b6771635dc751cbd6231274a3bbf87ae8b38c3319e5f54eb4e0a8186070727a19eb749b2e70068b7c505b1ed8b0dd7d6a595e2bf5db3601a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa04a9481f17c19c739ab1961ffdba488b234d37254da0ec7e95d8cf5d4ad54893ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03e5bfca057d64cd5c54c82f5e213f8e7993411a5a490c0b93358f6def507e8d4a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022e8402625a00808466a21171b90111d98301040c846765746889676f312e32312e3132856c696e75780000e0299c2ff8ae0fb860a41a9347a1766d7b59a6f4eb4434f89a5ff5e52df18b90baf4588374a65b578fdf85c4c605b325468883f22a49ce28bf1194955ae44b6de878a8def6b4c36cd5bb669be37d4a31bb7b48e45c7e0fe0d8fd43e86ba60871b6e1b7c731498d0df4f84882022ca0aeef6b8a15e0109c9838875b033b5c54d21c356cb5ddf395eb109b9b29ae694f82022da04a9481f17c19c739ab1961ffdba488b234d37254da0ec7e95d8cf5d4ad54893b80292058b3eeab2626c29d676db526a6a0d8b739a59f9d7971e5fd3e96192321e4759aa81a6bfdd5a211e3dca1d29f20fc5feffdb3261fb2afdd2fd9b4f9607fb201a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a000000000000000000000000000000000000000000000000000000000000000000ad5060ad206f9034fa04a6b366f150065827cf5954904fdca9da5073531b4aa5462e86636feb61890aca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03e5bfca057d64cd5c54c82f5e213f8e7993411a5a490c0b93358f6def507e8d4a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282022f8402625a00808466a21174b90111d98301040c846765746889676f312e32312e3132856c696e75780000e0299c2ff8ae0fb860a440c540974a6217ff340cbe742520fce50a18f18553f4816fdb43d9a74092ebb237ce4cce2a10f0e6d7b6ec58cf53990b91b8d2279eec1391748eab3a605cf1d900fa267dfc21cc8ebf35cb138c10287d49b3a4c1c5d18bd7727f74fa64e46ef84882022da04a9481f17c19c739ab1961ffdba488b234d37254da0ec7e95d8cf5d4ad54893b82022ea04a6b366f150065827cf5954904fdca9da5073531b4aa5462e86636feb61890ac806014de9b2c697f9b78ac9c86cdcc45bd19b3388569814a24bcbbe570a47561fd713af78490598f2d211f13cf1a5ed4bf299c1c1df8c677bd018b695c9f8339bf01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000120310ab041a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0d1c5c078d5c2983649e8200a84d8fef4d4c1ca8a06ed8f7be21f82c23a910edaa0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a0f9858d51200cb595d4f158c848af32e29fa61db4ddea7cde4006a7cbc306ef5880a03dc9ef066e7332efc09e4f620aab588d5465c1ed3b813c912928f1ffa44503a6a0a4aa3b0d5510f907876be1bff95c5867b088e8464e4ae75e45d016c5ac21c0faa00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa076094ead9021f5472bb12b03aeb521e09d71029dfa5dac90afa7cb44cbdfc5bd80f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a0579a97aa89dbeb98396792baa31c4a7ea8e2f41da084140f07bb4bd655b72dd5a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e565a8c9cbefc0c78b71cdf18eeb8206601e665778faa6b4dd23740f8dd8eeb0c7bcc8f49a1c900396aee02d1639ab7897ff2244a7876ea32e7a748c697d01345145485561305b24b3f0af694696c1b453b1174a1ea8c1135c247eb168864c9731254bc2f28077f99fe195b477ee699d79f40468aa30c2b62244b2e42bc54d19116d2348ac83461e2e0915d508adaf6af61cafa835c72fe6e9feb717dd4ddf95424e29b6384bd27c0d6c9c616d15cf7fdf0f2f9fc1a4fa9197251b196be32244e04db2de85453e0936b441c339a26d10cfa71b50996157a84dd67ec797a9ea61e4023c01d5bb28cce995c4c8329900b7b96e5402c02696f6f7b62972af4ee81f3f58afc12a448fdaaa7e6631e438625ca25c857a3727ea28e565a8c9cbefc0c78b71cdf18eeb8206601e665778faa6b4dd23740f8dd8eeb0c7bcc8f49a1c900396aee02d1639ab7897ff2a44b2e42bc54d19116d2348ac83461e2e0915d508adaf6af61cafa835c72fe6e9feb717dd4ddf95424e29b6384bd27c0d6c9c616d15cf7fdf0f2f9fc1a4fa9197251b196be32a44d9a13701eafb76870cb220843b8c6476824bfa15b822666ed599d40aa3bc13feb3ca5d5bc9d3ebe23d3460078c755a5ddbd85a0a58a217860fb0ea675b708a82b288f4b32a44e04db2de85453e0936b441c339a26d10cfa71b50996157a84dd67ec797a9ea61e4023c01d5bb28cce995c4c8329900b7b96e5402c02696f6f7b62972af4ee81f3f58afc130083808").to_vec();
        let any: Any = any.try_into().unwrap();
        let misbehaviour = Misbehaviour::try_from(any.clone()).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            misbehaviour.header_1.trusted_height(),
            ConsensusState {
                current_validators_hash: misbehaviour.header_1.current_epoch_validators_hash(),
                previous_validators_hash: misbehaviour.header_1.previous_epoch_validators_hash(),
                ..Default::default()
            },
        );
        mock_consensus_state.insert(
            misbehaviour.header_2.trusted_height(),
            ConsensusState {
                current_validators_hash: misbehaviour.header_2.current_epoch_validators_hash(),
                previous_validators_hash: misbehaviour.header_2.previous_epoch_validators_hash(),
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                fork_specs: vec![before_pascal()],
                ..Default::default()
            }),
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
                assert_eq!(prev_state[0].height, misbehaviour.header_1.trusted_height());
                assert_eq!(prev_state[1].height, misbehaviour.header_2.trusted_height());
                if let ValidationContext::Empty = context {
                    unreachable!("invalid validation context");
                }
            }
            other => unreachable!("err={:?}", other),
        };

        // assert fixture validity
        assert_eq!(misbehaviour.client_id, client_id);
        assert_eq!(
            misbehaviour.header_2.height(),
            misbehaviour.header_1.height()
        );
        assert_ne!(
            misbehaviour.header_2.block_hash(),
            misbehaviour.header_1.block_hash()
        );
    }

    #[test]
    fn test_error_submit_misbehaviour() {
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };

        let client = ParliaLightClient;
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // fail: exactly same block
        let mut any= hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212cf370a0b78782d7061726c69612d3112de1b0ab4060ab106f9032ea0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1c8402625a0080846699bcdab90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b86086dcdfb683f4965de8062063dd843775eeb55a1271b317a6d65ef7aadabb1e10a9327c9face4c69c331b914f3b24aeb4010b30d4c4a7007c67d7de812e9c7cca598c9b3b1e94679e90aeb94b790b19dce6bee8662126eecdb3b539efee6468b7f848820c1aa049430f5e612a0b37a9bab1b1c5003f02f3586a4e2ea9e84d8de511f879f30561820c1ba0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22803135a7c114e967442e0bc0996b3b083aae7638e142b3a145b8d966267fecb84141fcf58023341e1aeaf333bfe4d91349db198c157947780f46b1d476a892c25900a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d595a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1d8402625a0080846699bcddb90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860a410689613510c2087d762d49d42acb83f84b136e417e0567c8fbd693fd25cb36f794ae231b79101b94d700457f511120b7b2c8c0294c33b2d9728fa5d0a81a9c02901e28c3df1c840e7a4f7f6b5f150c3d7276b84a5f05d57a582ac6659692ff848820c1ba0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22820c1ca02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d59580dfca46ba06e40ca0191deacc05e2185acbfb04ca3ce23355f2b3d1be19667d096f33e5174260e4e5be857a49307dcf824f1b7e353c3be3e7bb4202c5bf4ae32b00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea0c0e82c0cda470def9ae9b03f55755b9cf0af015ae255bbb90a7969296918514aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1e8402625a0080846699bce0b90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860856d586a1618c0da1e906937b0a4c2596598a2d34e5cbf62063fc52ca9e5078fc962443b3a53166fabf69548b8d885ec08260a0d01293a3e61ba14d82e976f477f6ab2db2a8ae7c641cca0077c1770f472e7306ab43f8fecf762a95bc45ca1a5f848820c1ca02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d595820c1da0c0e82c0cda470def9ae9b03f55755b9cf0af015ae255bbb90a7969296918514a802a8efd919b1fe8bd679c8db7976de46350cfe3c2bdf67ec67e95c2f1c02909736bbb1bcdd798058072adc2e3cea6a16d519d1630e121539b8ccd77b1a7f84a1c00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180801203109b181a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0d8a8f0aaba741477e7d0c15b6a1759b3d842e346b35afd14219ecdd18188718ea0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a0bd63cc1cadd9ef7ffd41bb496484bff7c6ddbc3b29cf1a8b82d1f8f12bc6347680a0a74e307420bf9966d5db9a83ce48edc32c7a8e43328c6373de6875cefa04ad7aa0e502f113ade32bee3770b5a0117fa799c8812e5ab5a239e3878660c59c3537fda00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0d4182165b298d7b52b0f2064d19ab8bdad2b3955fa5b3d85c00673beb97e124480f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a03f47312ca98ac1f6ae9db9752c2a33529723b64e654d87f7847cee0382edfb55a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2244a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa2a448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2a44d9a13701eafb76870cb220843b8c6476824bfa15a82968379b116362f75bdb7cc4be8ca0ceea7c0f2e74be").to_vec();
        let any2= hex!("7c8f289cda6dcbc5edbb26400e1306c2de06f52a9a583dab99300138011ade1b0ab4060ab106f9032ea0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1c8402625a0080846699bcdab90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b86086dcdfb683f4965de8062063dd843775eeb55a1271b317a6d65ef7aadabb1e10a9327c9face4c69c331b914f3b24aeb4010b30d4c4a7007c67d7de812e9c7cca598c9b3b1e94679e90aeb94b790b19dce6bee8662126eecdb3b539efee6468b7f848820c1aa049430f5e612a0b37a9bab1b1c5003f02f3586a4e2ea9e84d8de511f879f30561820c1ba0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22803135a7c114e967442e0bc0996b3b083aae7638e142b3a145b8d966267fecb84141fcf58023341e1aeaf333bfe4d91349db198c157947780f46b1d476a892c25900a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d595a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1d8402625a0080846699bcddb90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860a410689613510c2087d762d49d42acb83f84b136e417e0567c8fbd693fd25cb36f794ae231b79101b94d700457f511120b7b2c8c0294c33b2d9728fa5d0a81a9c02901e28c3df1c840e7a4f7f6b5f150c3d7276b84a5f05d57a582ac6659692ff848820c1ba0c3ca2cd851054700e22f8313521399aacfcc225541cde7dfeca894f9b57d7c22820c1ca02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d59580dfca46ba06e40ca0191deacc05e2185acbfb04ca3ce23355f2b3d1be19667d096f33e5174260e4e5be857a49307dcf824f1b7e353c3be3e7bb4202c5bf4ae32b00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea0c0e82c0cda470def9ae9b03f55755b9cf0af015ae255bbb90a7969296918514aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a0d269e8b47a345f3a77343f46943f78480a96ff82a8466963fb4a29c0e2b66091a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820c1e8402625a0080846699bce0b90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860856d586a1618c0da1e906937b0a4c2596598a2d34e5cbf62063fc52ca9e5078fc962443b3a53166fabf69548b8d885ec08260a0d01293a3e61ba14d82e976f477f6ab2db2a8ae7c641cca0077c1770f472e7306ab43f8fecf762a95bc45ca1a5f848820c1ca02c07474042f3b317665fe4a233454a1ec921770d6429dd3eb0a23e812429d595820c1da0c0e82c0cda470def9ae9b03f55755b9cf0af015ae255bbb90a7969296918514a802a8efd919b1fe8bd679c8db7976de46350cfe3c2bdf67ec67e95c2f1c02909736bbb1bcdd798058072adc2e3cea6a16d519d1630e121539b8ccd77b1a7f84a1c00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180801203109b181a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0d8a8f0aaba741477e7d0c15b6a1759b3d842e346b35afd14219ecdd18188718ea0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a0bd63cc1cadd9ef7ffd41bb496484bff7c6ddbc3b29cf1a8b82d1f8f12bc6347680a0a74e307420bf9966d5db9a83ce48edc32c7a8e43328c6373de6875cefa04ad7aa0e502f113ade32bee3770b5a0117fa799c8812e5ab5a239e3878660c59c3537fda00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0d4182165b298d7b52b0f2064d19ab8bdad2b3955fa5b3d85c00673beb97e124480f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a03f47312ca98ac1f6ae9db9752c2a33529723b64e654d87f7847cee0382edfb55a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba822448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2244a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa2a448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2a44d9a13701eafb76870cb220843b8c6476824bfa15a82968379b116362f75bdb7cc4be8ca0ceea7c0f2e74be7c8f289cda6dcbc5edbb26400e1306c2de06f52a9a583dab9930013801").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehaviour
        let err = client
            .update_client(&ctx, client_id.clone(), any)
            .unwrap_err();
        assert_err(err, "UnexpectedSameBlockHash : 0-3100");

        // fail: invalid block
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: hex!(
                "5b514a7e8083146842c425a71aec83368ef4628442999a6d340d623ffb360c67"
            ),
            previous_validators_hash: hex!(
                "399334b2051da932262b42f25e5e59724c08df5c88d13c9d6bf5c51c33233aab"
            ),
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 3354), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(9999),
                fork_specs: vec![before_pascal()],
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        let mut any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212cf370a0b78782d7061726c69612d3112de1b0ab4060ab106f9032ea0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0225560657909c76bbd1111cfa8a11f7ade19c80a315f013a920031ce76562e3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1b8402625a0080846699bfd7b90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860b0b171c0b05dca088e0a163582339da1076da795a317c65f77441585d1446fda6692ce27df7b2b01ef2d419c2f8eb2f50b4e2f5856d9fb438f073c3e0aea72930333a6775d59096ce7560320504bb9bb4b17725edc5221491a3ac0bf64ec1f7ff848820d19a0e73c8182c6ff44e893b468600184209f9ffc5017be041533385658b98ee5675a820d1aa0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487b80649d4b1ea49d34532d24281cff713c1a1ffa9ad10ceaae118d02b19ec8a57bb4137e8ec449a3798de7cbec3a22d43d1377c84f045550e73e7100bb377df2753f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0225560657909c76bbd1111cfa8a11f7ade19c80a315f013a920031ce76562e3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1c8402625a0080846699bfdab90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b86083fcfb7f3c9d99995d330e6b953282f6c349af68cd4c523e1d635aa51ec49a2db651d824974ab9e7cf254e7e1b7e15cb0611ceb6adda365b8ee54d04c222b7f64dcacf94b4eb61671653396e1fe8840737444731d6c8d144d553a757e2327825f848820d1aa0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487b820d1ba018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33b80ddc0dfa730aa9a6de6089c20d1728803b04b4d7872a2b01c90e7cad663379a8a3f8676574fb5341ec662c890cae04fed92eaed9689c3b0c5421ea85fc3e42b5801a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea0220755141e26b1c68c8f887b41172aa93e3267f9f0ae7b49cfd1c7002558bcb4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0225560657909c76bbd1111cfa8a11f7ade19c80a315f013a920031ce76562e3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1d8402625a0080846699bfddb90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860af867e0589e50a2571bfdec447fae755aade11b113b67c7928ef8bd3225a6aa29a0e29b7ab24d4952ebcbfd320258a41071e5875b547f4265c7eeb45ab4989294328db719d94157619bca873e451c3709447ecb0fa349df1084da580bb46a425f848820d1ba018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33b820d1ca0220755141e26b1c68c8f887b41172aa93e3267f9f0ae7b49cfd1c7002558bcb4804613f2a8116641990a7d1ce90f946e079891aa1d7904c01e078df492f1ef4dff120465d060478da7542c7cd65621d68d47c35e20482385ca5af9d58329eeac1e00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180801203109a1a1a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0eec2a9e5f0342238c9790975e393915d8ef68ade66edfeb220210a2b13a89464a0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a08851197273e914fa4bdd7b07c2fec3f243a63d2298ed39c2b0a78c4f7da9ddd880a0a74e307420bf9966d5db9a83ce48edc32c7a8e43328c6373de6875cefa04ad7aa0e502f113ade32bee3770b5a0117fa799c8812e5ab5a239e3878660c59c3537fda00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0d4182165b298d7b52b0f2064d19ab8bdad2b3955fa5b3d85c00673beb97e124480f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a03f47312ca98ac1f6ae9db9752c2a33529723b64e654d87f7847cee0382edfb55a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba82244a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa2244d9a13701eafb76870cb220843b8c6476824bfa15a82968379b116362f75bdb7cc4be8ca0ceea7c0f2e74be7c8f289cda6dcbc5edbb26400e1306c2de06f52a9a583dab992a448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2a44a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07").to_vec();
        let any2 = hex!("f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa300138011ade1b0ab4060ab106f9032ea0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a00000000000000000000000000000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1b8402625a0080846699bfd7b90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860b0b171c0b05dca088e0a163582339da1076da795a317c65f77441585d1446fda6692ce27df7b2b01ef2d419c2f8eb2f50b4e2f5856d9fb438f073c3e0aea72930333a6775d59096ce7560320504bb9bb4b17725edc5221491a3ac0bf64ec1f7ff848820d19a0e73c8182c6ff44e893b468600184209f9ffc5017be041533385658b98ee5675a820d1aa0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487b80649d4b1ea49d34532d24281cff713c1a1ffa9ad10ceaae118d02b19ec8a57bb4137e8ec449a3798de7cbec3a22d43d1377c84f045550e73e7100bb377df2753f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0225560657909c76bbd1111cfa8a11f7ade19c80a315f013a920031ce76562e3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1c8402625a0080846699bfdab90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b86083fcfb7f3c9d99995d330e6b953282f6c349af68cd4c523e1d635aa51ec49a2db651d824974ab9e7cf254e7e1b7e15cb0611ceb6adda365b8ee54d04c222b7f64dcacf94b4eb61671653396e1fe8840737444731d6c8d144d553a757e2327825f848820d1aa0268b5cdf7f6414cb54b00626c619892e5f3b693d568d546ff76198667f9e487b820d1ba018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33b80ddc0dfa730aa9a6de6089c20d1728803b04b4d7872a2b01c90e7cad663379a8a3f8676574fb5341ec662c890cae04fed92eaed9689c3b0c5421ea85fc3e42b5801a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800ab4060ab106f9032ea0220755141e26b1c68c8f887b41172aa93e3267f9f0ae7b49cfd1c7002558bcb4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0225560657909c76bbd1111cfa8a11f7ade19c80a315f013a920031ce76562e3ea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002820d1d8402625a0080846699bfddb90111d98301040b846765746889676f312e32312e3132856c696e75780000ffcc693ef8ae03b860af867e0589e50a2571bfdec447fae755aade11b113b67c7928ef8bd3225a6aa29a0e29b7ab24d4952ebcbfd320258a41071e5875b547f4265c7eeb45ab4989294328db719d94157619bca873e451c3709447ecb0fa349df1084da580bb46a425f848820d1ba018b177b16b907b473a20b82a7c61d76f505a1f740c540e950f93c4210319a33b820d1ca0220755141e26b1c68c8f887b41172aa93e3267f9f0ae7b49cfd1c7002558bcb4804613f2a8116641990a7d1ce90f946e079891aa1d7904c01e078df492f1ef4dff120465d060478da7542c7cd65621d68d47c35e20482385ca5af9d58329eeac1e00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180801203109a1a1a9506f90312f901f1a094e7dcd05ddcc3923085b451330f3aa5ce5a628d6685506d99cb09b3aef0e11ea0eec2a9e5f0342238c9790975e393915d8ef68ade66edfeb220210a2b13a89464a0b116ef7733a93eed23f018027c116e60436a228a9f9173bb9b0c40eb71216da6a08851197273e914fa4bdd7b07c2fec3f243a63d2298ed39c2b0a78c4f7da9ddd880a0a74e307420bf9966d5db9a83ce48edc32c7a8e43328c6373de6875cefa04ad7aa0e502f113ade32bee3770b5a0117fa799c8812e5ab5a239e3878660c59c3537fda00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea070c0f30031f40c8017dbfc2ef008e6a3aae2e3105a654e0c5439b6104752882ea08f81903ec8515875682785142e1f92bdeaf65fccd5d0cf78b1ff2905a07e5883a03052420ba2d24a04d3f830584d3dbd6907b6d82bab84ddd806d03470e2c9d51ca06fb1a1498c2c8f93944a4f672ff4e982480ad181c835c0d8078159c517c7977aa013a426820f7b7249edc97cc5c002e653ac84b437f3ac12ac940c3d4b09e09827a09fbc54eac488b27315b09a1afa8d12f168e4c4cb5aea2d9a6ab5e7266da2f7e8a077c5e5cd5bd518bc509ee5e71790f1e42e492e23875b097e565cff8e809e7c8aa0d4182165b298d7b52b0f2064d19ab8bdad2b3955fa5b3d85c00673beb97e124480f8b18080a0dc77b6ae50b675036e77b31973c79ec60c28c0d2c57b03ad99c2acfff2f0cd4e80a03f47312ca98ac1f6ae9db9752c2a33529723b64e654d87f7847cee0382edfb55a05e0f116451aaa1baab3f3abff2793c8318050eeed6bf62d464d343a11d86eb2880808080808080a0abbb1987d09a71106f586030d1ab913bae0008e2a7dec0d08f2d60cd30fb2ac8a096c706907bfc6472dd88315cb8e21ee6f60a661cd8050065e2ba387023ee96858080f869a020b1e2b1f9852058ee0aaadca3c963f77f6483a1a51c644d79386bcada360583b846f8440180a0e39304f0ec064a98e4b0a96432dfb0a9e4c7fd0f26a6bbcf9c75bff68c51a7a9a0b3d632130dcb5cb583b47ec0623e59ca3703e6e2564f144272b597f3e3511ba82244a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa2244d9a13701eafb76870cb220843b8c6476824bfa15a82968379b116362f75bdb7cc4be8ca0ceea7c0f2e74be7c8f289cda6dcbc5edbb26400e1306c2de06f52a9a583dab992a448fdaaa7e6631e438625ca25c857a3727ea28e56593428ee663799df81ea82bc8445a7d93c891ef324b5f4438eb766bcf75fc405fb79d3f618fcdd17f107b374368ef512f2a44a7876ea32e7a748c697d01345145485561305b24903201f874819815e1a3f183c4addc814b71ec0e573e07f79ee9082926d82dd1711d6c45a9cc8841916d8563c2f80baa30013801").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehaviour
        let _ = Misbehaviour::try_from(any.clone()).unwrap();
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "UnexpectedHeaderRelation: 3355 3356");

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

    #[cfg(feature = "dev")]
    mod dev_test_min {
        use crate::client::test::{assert_err, MockClientReader};
        use crate::client::ParliaLightClient;
        use crate::client_state::ClientState;
        use crate::consensus_state::ConsensusState;
        use crate::header::hardfork::{MINIMUM_HEIGHT_SUPPORTED, MINIMUM_TIMESTAMP_SUPPORTED};
        use crate::misc::{new_height, new_timestamp};
        use light_client::{types::Any, LightClient};
        use std::collections::BTreeMap;
        use std::prelude::rust_2015::Box;
        use rstest::rstest;
        use crate::fixture::{localnet, Network};
        use crate::fork_spec::{ForkSpec, HeightOrTimestamp};

        #[rstest]
        #[case::localnet(localnet())]
        fn test_supported_value(#[case] hp: Box<dyn Network>) {
            let runner = |func: Box<dyn FnOnce(ClientState, ConsensusState) -> (ClientState, ConsensusState)>| {
                let (client_state , consensus_state, _, _) = hp.success_create_client();
                let client = ParliaLightClient;
                let mock_consensus_state = BTreeMap::new();
                let ctx = MockClientReader {
                    client_state: None,
                    consensus_state: mock_consensus_state,
                };
                let mut any_client_state: Any = client_state.try_into().unwrap();
                let mut any_consensus_state: Any = consensus_state.try_into().unwrap();
                let mut client_state = ClientState::try_from(any_client_state.clone()).unwrap();
                let mut consensus_state = ConsensusState::try_from(any_consensus_state.clone()).unwrap();
                (client_state, consensus_state) = func(client_state, consensus_state);
                let any_client_state: Any = client_state.try_into().unwrap();
                let any_consensus_state: Any = consensus_state.try_into().unwrap();
                client
                    .create_client(&ctx, any_client_state.clone(), any_consensus_state.clone())
            };

            let result = runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED - 1).unwrap();
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumTimestamp");

            let result = runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED - 1);
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumHeight");

            let result = runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED);
                client_state.fork_specs = vec![
                    ForkSpec {
                        height_or_timestamp: HeightOrTimestamp::Height(MINIMUM_HEIGHT_SUPPORTED - 1),
                        additional_header_item_count: 0,
                    }
                ];
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumHeightFork");

            let result = runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED);
                client_state.fork_specs = vec![
                    ForkSpec {
                        height_or_timestamp: HeightOrTimestamp::Time(MINIMUM_TIMESTAMP_SUPPORTED - 1),
                        additional_header_item_count: 0,
                    }
                ];
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumTimestampFork");

            // success
            runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED);
                client_state.fork_specs = vec![
                    ForkSpec {
                        height_or_timestamp: HeightOrTimestamp::Time(MINIMUM_TIMESTAMP_SUPPORTED),
                        additional_header_item_count: 0,
                    }
                ];
                (client_state, cons_state)
            })).unwrap();
        }
    }
}
