use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::{ClientError, Error};
use crate::header::Header;
use crate::message::ClientMessage;
use crate::misbehaviour::Misbehaviour;
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
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ProveState;
use patricia_merkle_trie::keccak::keccak_256;

use crate::commitment::{
    calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, resolve_account, verify_proof,
};
use crate::fork_spec::{verify_sorted_asc, HeightOrTimestamp};
use crate::header::constant::{MINIMUM_HEIGHT_SUPPORTED, MINIMUM_TIMESTAMP_SUPPORTED};
use prost::Message;

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
        let milli_timestamp = (timestamp.as_unix_timestamp_nanos() / 1_000_000) as u64;

        #[allow(clippy::absurd_extreme_comparisons)]
        if milli_timestamp < MINIMUM_TIMESTAMP_SUPPORTED {
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

        verify_sorted_asc(&client_state.fork_specs)?;

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

        let mut misbehaviour = misbehaviour;
        let trusted_consensus_state1 = ConsensusState::try_from(any_consensus_state1)?;
        let trusted_consensus_state2 = ConsensusState::try_from(any_consensus_state2)?;
        let new_client_state = client_state.check_misbehaviour_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state1,
            &trusted_consensus_state2,
            &mut misbehaviour,
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
        proof: Vec<u8>,
    ) -> Result<StateID, Error> {
        let prove_state = ProveState::decode(&*proof).map_err(Error::ProtoDecodeError)?;

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

        // verify account
        let account = resolve_account(
            &consensus_state.state_root,
            &decode_eip1184_rlp_proof(&prove_state.account_proof)?,
            &client_state.ibc_store_address,
        )
        .map_err(|e| Error::VerifyAccountError(alloc::boxed::Box::new(e)))?;

        // verify storage
        let storage_root = account
            .storage_root
            .try_into()
            .map_err(Error::UnexpectedStorageRoot)?;
        let storage_proof = decode_eip1184_rlp_proof(&prove_state.commitment_proof)?;
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

    use crate::fixture::{fork_spec_after_lorentz, fork_spec_after_pascal, localnet, Network};
    use crate::header::Header;

    use crate::errors::Error;
    use crate::fork_spec::HeightOrTimestamp;
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
                fork_specs: vec![fork_spec_after_pascal(), fork_spec_after_lorentz()],
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
        let (client_state, consensus_state, height, timestamp) = hp.success_create_client();
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
                assert_eq!(
                    (data.timestamp.as_unix_timestamp_nanos() / 1_000_000) as u64,
                    timestamp
                );
                assert_eq!(
                    data.timestamp.as_unix_timestamp_nanos() / 1_000_000,
                    cs.timestamp.as_unix_timestamp_nanos() / 1_000_000
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
            let (client_state, consensus_state, _, _) = hp.success_create_client();
            let client = ParliaLightClient;
            let mock_consensus_state = BTreeMap::new();
            let ctx = MockClientReader {
                client_state: None,
                consensus_state: mock_consensus_state,
            };
            let any_client_state: Any = client_state.try_into().unwrap();
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
                assert_eq!(new_consensus_state.state_root, header.state_root().clone());
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
    fn test_error_update_state_non_epoch_boundary_epochs_is_timestamp(
        #[case] hp: Box<dyn Network>,
    ) {
        let input = hp.success_update_client_non_epoch_input();
        let new_current_validators_hash = input.trusted_current_validators_hash;
        let new_previous_validators_hash = input.trusted_previous_validators_hash;
        let any: Any = input.header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient;
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: input.trusted_current_validators_hash,
            previous_validators_hash: input.trusted_previous_validators_hash,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, input.trusted_height), trusted_cs.clone());

        // Set fork spec is boundary timestamp
        let mut boundary_fs = fork_spec_after_lorentz();
        boundary_fs.height_or_timestamp =
            HeightOrTimestamp::Time(header.eth_header().target.milli_timestamp());
        let cs = ClientState {
            chain_id: hp.network(),
            ibc_store_address: hp.ibc_store_address(),
            latest_height: Height::new(0, input.trusted_height),
            fork_specs: vec![fork_spec_after_pascal(), boundary_fs],
            ..Default::default()
        };
        let ctx = MockClientReader {
            client_state: Some(cs.clone()),
            consensus_state: mock_consensus_state,
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert_err(err, "MissingForkHeightIntBoundaryCalculation");
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_update_state_non_epoch_update_fork_height(#[case] hp: Box<dyn Network>) {
        let input = hp.success_update_client_non_epoch_input();
        let new_current_validators_hash = input.trusted_current_validators_hash;
        let new_previous_validators_hash = input.trusted_previous_validators_hash;
        let any: Any = input.header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient;
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: input.trusted_current_validators_hash,
            previous_validators_hash: input.trusted_previous_validators_hash,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, input.trusted_height), trusted_cs.clone());

        // Set fork spec boundary timestamp is all[1]
        let mut boundary_fs = fork_spec_after_lorentz();
        boundary_fs.height_or_timestamp =
            HeightOrTimestamp::Time(header.eth_header().all[1].milli_timestamp());
        let cs = ClientState {
            chain_id: hp.network(),
            ibc_store_address: hp.ibc_store_address(),
            latest_height: Height::new(0, input.trusted_height),
            fork_specs: vec![fork_spec_after_pascal(), boundary_fs],
            ..Default::default()
        };
        let ctx = MockClientReader {
            client_state: Some(cs.clone()),
            consensus_state: mock_consensus_state,
        };
        let result = client.update_client(&ctx, client_id, any).unwrap();
        let data = match result {
            UpdateClientResult::UpdateState(data) => data,
            _ => unreachable!("invalid client result"),
        };
        let new_client_state = ClientState::try_from(data.new_any_client_state).unwrap();

        // update fork height
        assert_eq!(
            new_client_state.fork_specs[1].height_or_timestamp,
            HeightOrTimestamp::Height(header.eth_header().all[1].number)
        );
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
                "UnexpectedTrustedEpoch: {}",
                trusted_height.revision_height()
            ),
        );
    }

    #[test]
    fn test_success_verify_membership() {
        let proof_height = new_height(0, 738);
        let proof = hex!("0af505f902f2f90211a04f83ce967cc6c1a2529ccf2b54bb3be0822b7743744741920404fbda8e5bdb3aa0db8637d650a3f84e9866766025b2bb9a5a0e82140f3ac1d332f115fec1e3b0bda04cf087ca4528dc62a099390d1e88599fe43e360e2646f2067fa69774d22bb9d5a02fa8fb4f045ffee58682f7f7d1632a4b55512473503d73c265a97c621130ee8ba06e6b444bd057494f76216f671296fc77f71f989757f6286e308fc729a831c2daa08833397e80b9bf4db549c07e23998e023fd913b9efe4fe7579683f0688feaf02a09a256ea18698ff3c4769827a5c5535dd9f41d46fc8a534e7b51f8528491f621fa00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea0509d388bca267ead3cdeb2fb1da55193163896375582b79fced7df03cd42434aa0332fbd17735f4ee7db0b843666e1a9f5d3548badb90f4d16dca9e3f5a2f8665aa0b41e8d7ccbd1ec75dd4a330448c1ff914edd77397f847ceedfcb572ac7167b6aa02fe37b63b375e12fb0fdcc08811c4d4a2bb26a7c6e41bd7d908cbebe5a4b1178a0552ad5d23c543dd80f4d67a07ff4a37ebb9aafdd4642896cb473a1ad1b8600efa0d1d0d41dc046765964df5525c60b570da17d0ef87c7149260d72964bf7e280eaa0961b764de3cab4ab392b16c5144b545559450aa049b0575404432d040e8e1073a09acb2dbadb531e821eb8550792af7ab2c2e28e6407684d1ccf16c617e9f2e75980f871808080808080a05ebb69a6e5bc89b334b1cad75c8d55200c99c57898fb169e5c8546bb28b1f0208080a07d9dea58356b953bf7a7c795839d9dd16308c53d9eb944220ccd450abb8cc32a8080a0be86509add424551c0bb5c3cec1dd284c32757f219f0734656cd6513042f581280808080f869a02012683435c076b898a6cac1c03e41900e379104fefd4219d99f7908cb59cfb3b846f8440180a06ea5e7725bac4fdcc9462d77ec416efd003279f73a17a704ff07761638dd75a3a032494e8a0290ede55debb28d7a770918ee5249905e686dbfb522511502e6d1f512ef04f9026cf901d1a0162127af53c48811cc74cdf24e010964baeaec592221807055543c1be14c201ba031799f0839c6730a89f62d19f3a8c2f90648dfca3985861d989df03f7e6ea9a6a0f937a5894d7e171d02a2d836277767bbd69ae8b1864c52895a88d5d122b4ecaea05941e53568bf1fd6afed7ec75461710e0d67b8bbb72d3624acbad5ca353e4442a00dbc39c9b9ecaf901a5cacd446681d1b84276c0616bb2a142be9496f313382f880a061ec1614e1bd375100556e845545603fd281acb6615ced8af3196edef144a5aba0e46989a7771a48d24f9eedbee7b4efb32dd14f999e9b93b2399b4e0e7b6258c4a04585530cd9a77cfc46ffe70b4504dee31d8ad7bfa39ff5d8211ffbdb01c40defa0a777235f4b048421956fee718662f9308b4abfd1fb6b9922c67b2be6e623a37da032de982ffbb84f0a299cb7a3754690719719a79a03ef28b5bc1a476d16fff68ea042bd726cdc87e10a4ba8b83bebe34cf3bfa2729197b2cf5aa7de952efad3e1a4a065e3229e20dfd0b22ab4e93675f6a0b31d68a9639ebbe89348153658d046b300a0fb5fdb08b2ad9c2fd5cb6c7f9a2fe5aa7d809091e7075203dbda9c45c3bd634fa0f0342ad7c7a1501268fc9c0b31780b591caa57bf1754768896ddc35d80a270338080f85180a045a7754fcde5049be7c870b19247aad336ffcd4e10203b5e8f64039de5e4126880a09b7d0212148d0c50bd45d674a078f75ba616cdb1eef88e78947f1b442fa69ee680808080808080808080808080f843a020dc93aa2071d8fee619b0413af2f932685da696e8852d2c3c8dd087a6f0ffa6a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("b12f849b462b42954754ba3826ac6a97fb4f88ed820811a06640dd2edbc755ae");
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
        let proof_height = new_height(0, 738);
        let proof = hex!("0af505f902f2f90211a04f83ce967cc6c1a2529ccf2b54bb3be0822b7743744741920404fbda8e5bdb3aa06471fc474647b4776b34d1230c491cfd980bf33122f5956eff4eeefdf400431fa04cf087ca4528dc62a099390d1e88599fe43e360e2646f2067fa69774d22bb9d5a02824f5075c1fb398bab7ea258ee18a360b9639a1a31c6c604b13a492ca16394ea06e6b444bd057494f76216f671296fc77f71f989757f6286e308fc729a831c2daa099bf4775a4d089d01c6ffec506dfbb1eb64a13502604fa7477699b29e22b8b5ea03da8f11404097583100dd1eb02f762ccf0091ca84d6b118c644bf9cf900b7caaa00577e3e2c4649c5a23cbdabe0bbfed7cdf6e85c136d84d58127cdec86264ad6ea0509d388bca267ead3cdeb2fb1da55193163896375582b79fced7df03cd42434aa0332fbd17735f4ee7db0b843666e1a9f5d3548badb90f4d16dca9e3f5a2f8665aa0b41e8d7ccbd1ec75dd4a330448c1ff914edd77397f847ceedfcb572ac7167b6aa02fe37b63b375e12fb0fdcc08811c4d4a2bb26a7c6e41bd7d908cbebe5a4b1178a0552ad5d23c543dd80f4d67a07ff4a37ebb9aafdd4642896cb473a1ad1b8600efa0d1d0d41dc046765964df5525c60b570da17d0ef87c7149260d72964bf7e280eaa0961b764de3cab4ab392b16c5144b545559450aa049b0575404432d040e8e1073a09acb2dbadb531e821eb8550792af7ab2c2e28e6407684d1ccf16c617e9f2e75980f871808080808080a05ebb69a6e5bc89b334b1cad75c8d55200c99c57898fb169e5c8546bb28b1f0208080a07d9dea58356b953bf7a7c795839d9dd16308c53d9eb944220ccd450abb8cc32a8080a0be86509add424551c0bb5c3cec1dd284c32757f219f0734656cd6513042f581280808080f869a02012683435c076b898a6cac1c03e41900e379104fefd4219d99f7908cb59cfb3b846f8440180a06ea5e7725bac4fdcc9462d77ec416efd003279f73a17a704ff07761638dd75a3a032494e8a0290ede55debb28d7a770918ee5249905e686dbfb522511502e6d1f512ef04f9026cf901d1a0162127af53c48811cc74cdf24e010964baeaec592221807055543c1be14c201ba031799f0839c6730a89f62d19f3a8c2f90648dfca3985861d989df03f7e6ea9a6a0f937a5894d7e171d02a2d836277767bbd69ae8b1864c52895a88d5d122b4ecaea05941e53568bf1fd6afed7ec75461710e0d67b8bbb72d3624acbad5ca353e4442a00dbc39c9b9ecaf901a5cacd446681d1b84276c0616bb2a142be9496f313382f880a061ec1614e1bd375100556e845545603fd281acb6615ced8af3196edef144a5aba0e46989a7771a48d24f9eedbee7b4efb32dd14f999e9b93b2399b4e0e7b6258c4a04585530cd9a77cfc46ffe70b4504dee31d8ad7bfa39ff5d8211ffbdb01c40defa0a777235f4b048421956fee718662f9308b4abfd1fb6b9922c67b2be6e623a37da032de982ffbb84f0a299cb7a3754690719719a79a03ef28b5bc1a476d16fff68ea042bd726cdc87e10a4ba8b83bebe34cf3bfa2729197b2cf5aa7de952efad3e1a4a065e3229e20dfd0b22ab4e93675f6a0b31d68a9639ebbe89348153658d046b300a0fb5fdb08b2ad9c2fd5cb6c7f9a2fe5aa7d809091e7075203dbda9c45c3bd634fa0f0342ad7c7a1501268fc9c0b31780b591caa57bf1754768896ddc35d80a270338080f85180a045a7754fcde5049be7c870b19247aad336ffcd4e10203b5e8f64039de5e4126880a09b7d0212148d0c50bd45d674a078f75ba616cdb1eef88e78947f1b442fa69ee680808080808080808080808080f843a020dc93aa2071d8fee619b0413af2f932685da696e8852d2c3c8dd087a6f0ffa6a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("8617db342e8a02bf863ef25096db1ec2b5d665df743e789828ba626c88d41cf3");
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
                ibc_store_address: hex!("aa43d337145E8930d01cb4E60Abf6595C692921E"),
                ibc_commitments_slot: hex!(
                    "1ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900"
                ),
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
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212c6300a0b78782d7061726c69612d31128c170af6060af306f90370a0bcf423276bee4dbb0205f395d5f73dab513d7cb3e79a634f969df347537f3cc9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0df3605ab1ded1b02408bad8ac4d1391abea1cccfd90d0f332951f294375d0b8fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202c78402625a00808467d00ec1b90111d883010505846765746888676f312e32332e37856c696e75780000004d2622aaf8ae03b86080ede2b1f76367a7a1e2d9671f6c3954ce7143a5b2c74b56a998d41cff1dd4432ec7ac4d9c12af18b78efaa8ab609e8d19a7f90cf1a568346eff5d8909555a9c18ba98f3dead20f850878d34c4dc5f491a0fef1b49799bc2d4fcaf8ef9c28b02f8488202c5a0dae075ce24140e7d270976767ffdd1c09774dbba5a020d9c8ae428f2bfdb73718202c6a0bcf423276bee4dbb0205f395d5f73dab513d7cb3e79a634f969df347537f3cc9800c31980d8fe3ab00b710e2403a13b808aed6ebfd899385d09e4bf8be64997dd62bbec57bb4624ce6c123880636713340c31c04fbe907e554397b64e573cffa2100a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0af95ffe55ab4f551c803abcd747079fac133cbbb9e241ac8e64aa3ebbfbb68f4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a04f8e7b8d1e6b3a9c3586a06c8c1b6d3551d604b7ae0b3bdfe416f863eddc7354a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202c88402625a00808467d00ec4b90111d883010505846765746888676f312e32332e37856c696e75780000004d2622aaf8ae03b8609120dc5ff1026be3223eabf3f5f2ec184d8edd6b5bdfd7849faa545f6180c62fa4c98f15704df073cdacddefaaff4fb20cfc6ae3dbba48519c4bb6b63a8f844ca9df18c90a98e66d9d0be15a53d6bac23853c355241a865abe06b39fb5033743f8488202c6a0bcf423276bee4dbb0205f395d5f73dab513d7cb3e79a634f969df347537f3cc98202c7a0af95ffe55ab4f551c803abcd747079fac133cbbb9e241ac8e64aa3ebbfbb68f480536f03148a0f51e1320140145cad7f5d9abaee94cad967f856bbb54dcf905c9039c1ef36d50a279cae95a351c1338ce5f07faf7f3db083b5b9161bff9e10f28f01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0a46c2663376b09f02207da096c42dee09822a3975db771c4d1e1332737d1bcd3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0abbb6e40d3d188bc7b4203a9905c5a910f789801b5f6a1803e76165f3edf3405a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202c98402625a00808467d00ec7b90111d883010505846765746888676f312e32332e37856c696e75780000004d2622aaf8ae03b860a95c96c9095eae79fcd12d81fd298cd048b46eec0019ac39f35331b2b9c19b68f29e231e3cb9f9761ac5fa8875d6cbd60a10ae994087ea0b876181b0c0571173503000b626db0041d1ddadfc5bc8a645b8d199508137df1fd14264c16e8a5286f8488202c7a0af95ffe55ab4f551c803abcd747079fac133cbbb9e241ac8e64aa3ebbfbb68f48202c8a0a46c2663376b09f02207da096c42dee09822a3975db771c4d1e1332737d1bcd380684d242a478031c74aa937c29cbe388f8103ada3d95cc6a539ead39fe16fd82731e8d0c53516a7f488cfc1b438498042994ca54d05b37b0103330726d96724b300a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310c6051a44a7876ea32e7a748c697d01345145485561305b24a485dbaadce4a8c2a53776a976aba7eb234f626cdabdef4f5bc107f959d7670b8b16977cd6ed75deaada04a5b735f8b21a44d9a13701eafb76870cb220843b8c6476824bfa1599b98f72c9afc9aeb469dae26bd849e3ced8ec8888e6ec16f8f7c9eeda8f9f620b4aeb01ffa4d022167b23fb4c3fc66c22448fdaaa7e6631e438625ca25c857a3727ea28e565b3578eaae8fa56b45ca90f5620afe437f7b41fd8c4f8e2428cf83be168dd93288a8d26406a850de67b1ff6ddf9bfdb692244a7876ea32e7a748c697d01345145485561305b24a485dbaadce4a8c2a53776a976aba7eb234f626cdabdef4f5bc107f959d7670b8b16977cd6ed75deaada04a5b735f8b2280430081aa7190af9060af606f90373a00dc20b49a0b4f16f36f4131ed92d3724c48443e83a3d09c4963c9b008402534ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a00725a2f9efc4850fe004341f398c3c17040f8ff8a84f747fb729bdc50259af89a05d74a9f8937eb042045ad57c519824df058a77e550c7ef9b531afda823c20863a0ecaaa68cb6eda61c2c6ee5f366f1d13cb5d2986fb18d22989d880db8645cadceb9010000000000000000000000004000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002010000000000000000000000000010000080020000200000000000000000000080000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000020000000000000002008400000020000000000000000000000000000000000000000000000000000000000000000000000000000000000080000104002000000000000000000000000010000040000010000008000000000004000000000000000028202c78402625a008306ed738467d00eb8b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb86084128e77dacaf3c448d5847ff3eaab289ba436c999b3d21d38b2c38c1174554cded80770419dab4f3dbc25b13d183c2513c94432f4b1614e0d80ee272980f34a2eb25b9f638e1622a400e65bcf1f2e8afcd121cf9d670ed5d123245622ba90bef8488202c5a04ae0ada31ecd1b5d875c91aa0a58b2ae6b49667741cf8fd58443ece5a85fb6948202c6a00dc20b49a0b4f16f36f4131ed92d3724c48443e83a3d09c4963c9b008402534b805bd310e4c1f45a2b7977d54cad5cc616d613f313b811eb94e3140aa748b7e4251b0fb8a5e3d836b01ebfb33d4de5753b1277b8be02fef476bdb7fb297e0bcb3100a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0b8bcb3864d490b5d75b889999f923decd62bccb032c39f577861ed5916fc779fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0a58f35b982fb99d7cecefae42654267108a4ea87cf8130998120834984f95945a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202c88402625a00808467d00ebbb90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b96bd8ba80bcea4e018b959c3eebc688fe3b27a1ff1e5b03248fb5edf64c6b5285aa344f83d54a9459a286ddc267959e187dda37761e4e3cf72dddb3f1c946b72d93a9523bc45d1e027de549d24aa9a16caea89ab2357b583d0b44e021c95380f8488202c6a00dc20b49a0b4f16f36f4131ed92d3724c48443e83a3d09c4963c9b008402534b8202c7a0b8bcb3864d490b5d75b889999f923decd62bccb032c39f577861ed5916fc779f8079f0dc578581fa2b2e270353cbf3ca150676a27d0aa31a6b270d8fea1fa2ef56314c07f1aa7d8ca1e4448c37b7f8cca695fe271717634e88369b807f660a762100a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0bbdf9cc08305a46cdbe0740b15338c87674b62906cc0e4c8c9033813fe46b5d0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0d9f03ddb3371cd8ce245ea85e499cb763ecb68071adecc6c3c74f75136cb9e6da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202c98402625a00808467d00ebeb90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860a5224150f6a842a965128cb719c859faf5d080acfda9b33e97788fb2e079cf602f2b24a7619851317dddbd8d8f931fea0886287914952c4654e012802519451dbe0f275e0813a201e62cbd5d7e71581f6a7117d2a67d4b7829a9b3f73ef7b4def8488202c7a0b8bcb3864d490b5d75b889999f923decd62bccb032c39f577861ed5916fc779f8202c8a0bbdf9cc08305a46cdbe0740b15338c87674b62906cc0e4c8c9033813fe46b5d080dd912614993f9ee58208ed05889671e284c0f46904e7c16c8c81b023b16567c835a0b21f6e3b12c9d776b3ac0c53ab0631961919e26053112f2aa6e0074d0bb200a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310c5051a44a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb1a44b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81721a44d9a13701eafb76870cb220843b8c6476824bfa15933e9ee732cad53fcaab7a262f923a6c5a2f19033136dd925786b0890af8e44573f71695bc10fc25168ae1b41e5c92331a44e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486822448fdaaa7e6631e438625ca25c857a3727ea28e5659952928ee3ab47ef980231cd0ed75ebcce668b23ec23d21c7fc4ac91ceb2dc605973bd4914e6ae4d29db2d349441cb772244a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb2244b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81722244e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486828093007").to_vec();
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
                fork_specs: vec![fork_spec_after_pascal(), fork_spec_after_lorentz()],
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
        let mut any= hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212db320a0b78782d7061726c69612d3112a4190af6060af306f90370a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0f213a434eee1a6f27d9891a7c29c76641ffa43f4cef91a264824477eaea8300fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202da8402625a00808467d00ef1b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b9cc1c4d529d31592a873c3cb3afd6bac1766302f424652c3fbedcbec2da7a7f99249f88dd1a13a1b22059c8b393540d187fb2628c89bda549a7010a2488533d6b3cf9bad7142f9ea61eff699dddf5a4e6423b4aecabf8dc499c923f2cdfbfa9f8488202d8a0b0e9d1ddd59db45429b1ae9d4c01812e7bdbe7a8822d32855617844f10ed5b748202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b804721ffbf07fc83f2f1cc3773881b3f7868b707198e84d42ac1bacf40039a8bb13009d78f96ff8e8d1552ae3583d001101aefcba4d6a827527fdce1b7e91afb0401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a67a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada094de24b42126f642e0497a72d77d0c583fb9c6230f7a6dba7e54efa97e13c627a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202db8402625a00808467d00ef4b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b50822e55669b92492ecc5a42229fe7c03e0d0116a0449e3d2897fc32e134e0a601a9a49c13fd8eea94162858a83229d086639a1cef8ea3a3210937ea0aec4f140d9ccae24ed535c9ddb75024d4d58133c0483e352bd634af301da84f98bb154f8488202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b8202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a6780b6bdc9a4de82e5d16cb1868bea7a98df85879e37ff283cc4f5ed0604b58cbbdc60faa7b6dc3fb519c35ffe8a2b2cd34da95f65087c905345bae6ef8d319c5d3e01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0305c4387cd456db6642b98fb5a615619af15a1c900f612501c20793f24e91257a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202dc8402625a00808467d00ef7b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb8608871ce67969e2b836797cae67245c47e43d848aa91671b27bdf17c64a1b8567a2a8726d677cb7058e503aa5308f296a51574f47028fe8246d07a1c8c1ed49bfaacecdb0d0e93b97da8cc8e067022e2f89636aa38f7d22f4944e1b6c3158145b9f8488202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a678202dba06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319e80869fda554f1f7821370f876ff60b3f4cab712df1a46f53cabea77f19e16a98af26f85c7cfb4cb482b1851ebc25e8e1482e70840c77075e7636a165caad92756600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310d9051a44a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb1a44b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81721a44d9a13701eafb76870cb220843b8c6476824bfa15933e9ee732cad53fcaab7a262f923a6c5a2f19033136dd925786b0890af8e44573f71695bc10fc25168ae1b41e5c92331a44e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486822448fdaaa7e6631e438625ca25c857a3727ea28e5659952928ee3ab47ef980231cd0ed75ebcce668b23ec23d21c7fc4ac91ceb2dc605973bd4914e6ae4d29db2d349441cb772244a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb2244b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81722244e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b16984").to_vec();
        let any2= hex!("5c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a4868280930071aa4190af6060af306f90370a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0f213a434eee1a6f27d9891a7c29c76641ffa43f4cef91a264824477eaea8300fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202da8402625a00808467d00ef1b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b9cc1c4d529d31592a873c3cb3afd6bac1766302f424652c3fbedcbec2da7a7f99249f88dd1a13a1b22059c8b393540d187fb2628c89bda549a7010a2488533d6b3cf9bad7142f9ea61eff699dddf5a4e6423b4aecabf8dc499c923f2cdfbfa9f8488202d8a0b0e9d1ddd59db45429b1ae9d4c01812e7bdbe7a8822d32855617844f10ed5b748202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b804721ffbf07fc83f2f1cc3773881b3f7868b707198e84d42ac1bacf40039a8bb13009d78f96ff8e8d1552ae3583d001101aefcba4d6a827527fdce1b7e91afb0401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a67a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada094de24b42126f642e0497a72d77d0c583fb9c6230f7a6dba7e54efa97e13c627a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202db8402625a00808467d00ef4b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b50822e55669b92492ecc5a42229fe7c03e0d0116a0449e3d2897fc32e134e0a601a9a49c13fd8eea94162858a83229d086639a1cef8ea3a3210937ea0aec4f140d9ccae24ed535c9ddb75024d4d58133c0483e352bd634af301da84f98bb154f8488202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b8202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a6780b6bdc9a4de82e5d16cb1868bea7a98df85879e37ff283cc4f5ed0604b58cbbdc60faa7b6dc3fb519c35ffe8a2b2cd34da95f65087c905345bae6ef8d319c5d3e01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0305c4387cd456db6642b98fb5a615619af15a1c900f612501c20793f24e91257a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202dc8402625a00808467d00ef7b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb8608871ce67969e2b836797cae67245c47e43d848aa91671b27bdf17c64a1b8567a2a8726d677cb7058e503aa5308f296a51574f47028fe8246d07a1c8c1ed49bfaacecdb0d0e93b97da8cc8e067022e2f89636aa38f7d22f4944e1b6c3158145b9f8488202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a678202dba06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319e80869fda554f1f7821370f876ff60b3f4cab712df1a46f53cabea77f19e16a98af26f85c7cfb4cb482b1851ebc25e8e1482e70840c77075e7636a165caad92756600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310d9051a44a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb1a44b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81721a44d9a13701eafb76870cb220843b8c6476824bfa15933e9ee732cad53fcaab7a262f923a6c5a2f19033136dd925786b0890af8e44573f71695bc10fc25168ae1b41e5c92331a44e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486822448fdaaa7e6631e438625ca25c857a3727ea28e5659952928ee3ab47ef980231cd0ed75ebcce668b23ec23d21c7fc4ac91ceb2dc605973bd4914e6ae4d29db2d349441cb772244a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb2244b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81722244e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486828093007").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehaviour
        let err = client
            .update_client(&ctx, client_id.clone(), any)
            .unwrap_err();
        assert_err(err, "UnexpectedSameBlockHash : 0-730");

        // fail: invalid block
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: hex!(
                "3d54d2721533c6c4f6b16867838d8e5b536f99733560b4de6b7231ca8755fcfc"
            ),
            previous_validators_hash: hex!(
                "6c7878638fcd4ff99c05131c23b62dec729ef854d129b6deb38af8268dc9478b"
            ),
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 729), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(9999),
                fork_specs: vec![fork_spec_after_pascal(), fork_spec_after_lorentz()],
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        let mut any= hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212db320a0b78782d7061726c69612d3112a4190af6060af306f90370a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0f213a434eee1a6f27d9891a7c29c76641ffa43f4cef91a264824477eaea8300fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202da8402625a00808467d00ef1b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b9cc1c4d529d31592a873c3cb3afd6bac1766302f424652c3fbedcbec2da7a7f99249f88dd1a13a1b22059c8b393540d187fb2628c89bda549a7010a2488533d6b3cf9bad7142f9ea61eff699dddf5a4e6423b4aecabf8dc499c923f2cdfbfa9f8488202d8a0b0e9d1ddd59db45429b1ae9d4c01812e7bdbe7a8822d32855617844f10ed5b748202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b804721ffbf07fc83f2f1cc3773881b3f7868b707198e84d42ac1bacf40039a8bb13009d78f96ff8e8d1552ae3583d001101aefcba4d6a827527fdce1b7e91afb0401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a67a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada094de24b42126f642e0497a72d77d0c583fb9c6230f7a6dba7e54efa97e13c627a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202db8402625a00808467d00ef4b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b50822e55669b92492ecc5a42229fe7c03e0d0116a0449e3d2897fc32e134e0a601a9a49c13fd8eea94162858a83229d086639a1cef8ea3a3210937ea0aec4f140d9ccae24ed535c9ddb75024d4d58133c0483e352bd634af301da84f98bb154f8488202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b8202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a6780b6bdc9a4de82e5d16cb1868bea7a98df85879e37ff283cc4f5ed0604b58cbbdc60faa7b6dc3fb519c35ffe8a2b2cd34da95f65087c905345bae6ef8d319c5d3e01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0305c4387cd456db6642b98fb5a615619af15a1c900f612501c20793f24e91257a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202dc8402625a00808467d00ef7b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb8608871ce67969e2b836797cae67245c47e43d848aa91671b27bdf17c64a1b8567a2a8726d677cb7058e503aa5308f296a51574f47028fe8246d07a1c8c1ed49bfaacecdb0d0e93b97da8cc8e067022e2f89636aa38f7d22f4944e1b6c3158145b9f8488202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a678202dba06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319e80869fda554f1f7821370f876ff60b3f4cab712df1a46f53cabea77f19e16a98af26f85c7cfb4cb482b1851ebc25e8e1482e70840c77075e7636a165caad92756600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310d9051a44a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb1a44b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81721a44d9a13701eafb76870cb220843b8c6476824bfa15933e9ee732cad53fcaab7a262f923a6c5a2f19033136dd925786b0890af8e44573f71695bc10fc25168ae1b41e5c92331a44e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486822448fdaaa7e6631e438625ca25c857a3727ea28e5659952928ee3ab47ef980231cd0ed75ebcce668b23ec23d21c7fc4ac91ceb2dc605973bd4914e6ae4d29db2d349441cb772244a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb2244b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81722244e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b16984").to_vec();
        let any2= hex!("5c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a4868280930071aa4190af6060af306f90370a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada00000000000000000000000000000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202da8402625a00808467d00ef1b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b9cc1c4d529d31592a873c3cb3afd6bac1766302f424652c3fbedcbec2da7a7f99249f88dd1a13a1b22059c8b393540d187fb2628c89bda549a7010a2488533d6b3cf9bad7142f9ea61eff699dddf5a4e6423b4aecabf8dc499c923f2cdfbfa9f8488202d8a0b0e9d1ddd59db45429b1ae9d4c01812e7bdbe7a8822d32855617844f10ed5b748202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b804721ffbf07fc83f2f1cc3773881b3f7868b707198e84d42ac1bacf40039a8bb13009d78f96ff8e8d1552ae3583d001101aefcba4d6a827527fdce1b7e91afb0401a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a67a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada094de24b42126f642e0497a72d77d0c583fb9c6230f7a6dba7e54efa97e13c627a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202db8402625a00808467d00ef4b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb860b50822e55669b92492ecc5a42229fe7c03e0d0116a0449e3d2897fc32e134e0a601a9a49c13fd8eea94162858a83229d086639a1cef8ea3a3210937ea0aec4f140d9ccae24ed535c9ddb75024d4d58133c0483e352bd634af301da84f98bb154f8488202d9a06bb5eb76f326c67c7715cc402296353a74907abdcc384f551c1427dea1cb6e3b8202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a6780b6bdc9a4de82e5d16cb1868bea7a98df85879e37ff283cc4f5ed0604b58cbbdc60faa7b6dc3fb519c35ffe8a2b2cd34da95f65087c905345bae6ef8d319c5d3e01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550af6060af306f90370a06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada0305c4387cd456db6642b98fb5a615619af15a1c900f612501c20793f24e91257a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028202dc8402625a00808467d00ef7b90111d883010505846765746888676f312e32332e37856c696e7578000000ff037d50f8ae0fb8608871ce67969e2b836797cae67245c47e43d848aa91671b27bdf17c64a1b8567a2a8726d677cb7058e503aa5308f296a51574f47028fe8246d07a1c8c1ed49bfaacecdb0d0e93b97da8cc8e067022e2f89636aa38f7d22f4944e1b6c3158145b9f8488202daa0ee5f12de6366bb1488fa849c748b51e53a32d7daab6499ce8ab0d23cad617a678202dba06c2e2a3f0dc9f7bbc40ec103c97b49ec079c88c00abf3cdd966922c557cc319e80869fda554f1f7821370f876ff60b3f4cab712df1a46f53cabea77f19e16a98af26f85c7cfb4cb482b1851ebc25e8e1482e70840c77075e7636a165caad92756600a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120310d9051a44a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb1a44b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81721a44d9a13701eafb76870cb220843b8c6476824bfa15933e9ee732cad53fcaab7a262f923a6c5a2f19033136dd925786b0890af8e44573f71695bc10fc25168ae1b41e5c92331a44e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486822448fdaaa7e6631e438625ca25c857a3727ea28e5659952928ee3ab47ef980231cd0ed75ebcce668b23ec23d21c7fc4ac91ceb2dc605973bd4914e6ae4d29db2d349441cb772244a7876ea32e7a748c697d01345145485561305b24a5d7d2e39dd93e5df8bb135ce476c313de541f8029f742c84cce3ab86ce1f56006167491c71c10856b89a9cc07a5b9cb2244b2e42bc54d19116d2348ac83461e2e0915d508ad92becd1a47f6eaec1583ebdd4990b518666e0cee67961b5cfb24bf538d7ea370bed973f07824cd5c31a1a091fbee81722244e04db2de85453e0936b441c339a26d10cfa71b50a498f4680dc9f07facc7e1bceafed4dc1efe3a32b169845c4b8f96da8de788ddaeb513ee0a898e1410b3791e2a4a486828093007").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        // check if misbehaviour
        let _ = Misbehaviour::try_from(any.clone()).unwrap();
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert_err(err, "UnexpectedHeaderRelation: 730 731");

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
        use crate::fixture::{localnet, Network};
        use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
        use crate::header::constant::{MINIMUM_HEIGHT_SUPPORTED, MINIMUM_TIMESTAMP_SUPPORTED};
        use crate::misc::{new_height, new_timestamp};
        use light_client::{types::Any, LightClient};
        use rstest::rstest;
        use std::collections::BTreeMap;
        use std::prelude::rust_2015::Box;

        #[rstest]
        #[case::localnet(localnet())]
        fn test_supported_value(#[case] hp: Box<dyn Network>) {
            let runner = |func: Box<
                dyn FnOnce(ClientState, ConsensusState) -> (ClientState, ConsensusState),
            >| {
                let (client_state, consensus_state, _, _) = hp.success_create_client();
                let client = ParliaLightClient;
                let mock_consensus_state = BTreeMap::new();
                let ctx = MockClientReader {
                    client_state: None,
                    consensus_state: mock_consensus_state,
                };
                let mut any_client_state: Any = client_state.try_into().unwrap();
                let mut any_consensus_state: Any = consensus_state.try_into().unwrap();
                let mut client_state = ClientState::try_from(any_client_state.clone()).unwrap();
                let mut consensus_state =
                    ConsensusState::try_from(any_consensus_state.clone()).unwrap();
                (client_state, consensus_state) = func(client_state, consensus_state);
                let any_client_state: Any = client_state.try_into().unwrap();
                let any_consensus_state: Any = consensus_state.try_into().unwrap();
                client.create_client(&ctx, any_client_state.clone(), any_consensus_state.clone())
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
                client_state.fork_specs = vec![ForkSpec {
                    height_or_timestamp: HeightOrTimestamp::Height(MINIMUM_HEIGHT_SUPPORTED - 1),
                    additional_header_item_count: 0,
                    epoch_length: 200,
                }];
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumHeightFork");

            let result = runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED);
                client_state.fork_specs = vec![ForkSpec {
                    height_or_timestamp: HeightOrTimestamp::Time(MINIMUM_TIMESTAMP_SUPPORTED - 1),
                    additional_header_item_count: 0,
                    epoch_length: 200,
                }];
                (client_state, cons_state)
            }));
            assert_err(result.unwrap_err(), "UnsupportedMinimumTimestampFork");

            // success
            runner(Box::new(|mut client_state, mut cons_state| {
                cons_state.timestamp = new_timestamp(MINIMUM_TIMESTAMP_SUPPORTED).unwrap();
                client_state.latest_height = new_height(0, MINIMUM_HEIGHT_SUPPORTED);
                client_state.fork_specs = vec![ForkSpec {
                    height_or_timestamp: HeightOrTimestamp::Time(MINIMUM_TIMESTAMP_SUPPORTED),
                    additional_header_item_count: 0,
                    epoch_length: 200,
                }];
                (client_state, cons_state)
            }))
            .unwrap();
        }
    }
}
