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
    use time::macros::datetime;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;

    use crate::header::Header;
    use crate::misbehaviour::Misbehaviour;
    use crate::misc::{new_height, ChainId, Hash};

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

    #[test]
    fn test_success_update_state_neighboring_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212b2520ab3110ab011f908ada0c1b3a1b35c53d9860d1464d20138e6271602e00ea876757d7106016ce83466f3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda0db01e241c7ed90c7fafad6ebbd727b14b7633bd336a97fc9761bc37b12aad0f4a0cc1257fae1a1a2648190df64c111671f764e7729157d87a6a75046060e937d53a0791ba98205dc99116e137099424fe843a0765cb96f82d2c597a43da570355351b9010003b2fbb5134f56fe987ffbd6bf693df76b135948febbc7f808dea7f70e3a59a2d7f8bdeed8263f57c7d336fd0bdf3ff9df186a1e557df4edd987f8fefeafa6f0e4f385ed7df6bffd57c1d75f5a8e95fe7ff45b2588f66cfc8affdfd4decc77d8f6feb97f2ad701308ff50f677fe79af5ae4cd4fae8c7ed0cd7fdcc3cd0d3feaf976ec2daebddaa766d8d9e689ff7f7bfbf646fa72897dfcedff9b57bf9cb1ff1e378ca85df3607bcaf2b65dc7fc68dfefe3f1ea73cfff9174ad7e82f73ed7ff3e4a09f9fd97d794777aadfecdbcb77bf7b7ffcbbdff4615c4314fbfedb6ff68959f3fa71efdcd44bff3e6f44b655e388bfd4bcf8fa11a95f67fbfff8eb2af9cd028402211e008408583b0084011b48aa8465ba3192b906add883010307846765746888676f312e32302e35856c696e757800000001a091a0150bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab03f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a61dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25685b1ded8013785d6623cc18d214320b6bb647598a60f82a7bcf74b4cb053b9bfe83d0ed02a84ebb10865dfdd8e26e7535c43a1cccd268e860f502216b379dfc9971d35872b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a517ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694859bb832254baf4e8b4cc26bd2b52b31389b56e98bab764a39ff81dad720d5691b852898041a3842e09ecbac8025812d51b32223d8420e6ae51a01582220a10f7722de67c1a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b741b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de7b4dd66d7c2c7e57f628210187192fb89d4b99dd4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cdcc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a419ce2fd7544e0b2cc94692d4a704debef7bcb61328b64abe25614c9cfd32e456b4d521f29c8357f4af4606978296c9be93494072ac05fa86e3d27cc8d66e65000f8ba33fbbd1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce739e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d21ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c192183ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5bef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0f8b5831bdbffb860a1b2529dc7c1cb57e9b80a29d82ca0fafad5245fb7947158cc585b96609a8dfd005f2b9d111cad1d663d506cfc8a2cd2111831cb0863c5a92007a91dc504a32e496d6e3e392258e7fd47d0ed7e01a8448a1f9967fae814829c4104b2d2f27b9df84c8402211dfea0567d4dd0ea048881bb924343a4e69bd8164a03ab881739dd0ce5cde9c3ab13408402211dffa0c1b3a1b35c53d9860d1464d20138e6271602e00ea876757d7106016ce83466f380e863967543e27479ee79f33ab2ee5e276b0970a1565d96767e3ff55ab16ce0ac421983faa09eea6aa8e769fdf8182251e9225e39b3feef23a302ba897c41d20c01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9e060a9b06f90318a029bf36156df8e525f809db876705baae274b69205fd5716448392648e0941c52a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794295e26495cef6f69dfa69911d9d8e4f3bbadb89ba06f43ef7855ea56f036992abd7d992004d9fb11c0f16ac7efad79698cfd468c55a048f43cb851c8a35dcaaa6216f8f041da9e548f6b699b3b60bd095409044c4542a0f5ca7a7a61593ea62df7e100ea541399629e3f3f90975ae4127c2cf46670f029b90100f93e770a65dbd3dedfe67ddcfad59d7bdc5ca5259f7eb5bd97efe35b4667e55aee7cdd8bf2715d8b3baf7dbbd73fa3b3d11fd1790ebaece8ad723bd8c3bce78837acd76ef9e95c7cd5ecfffb97a21ff6b8f4a8f52af4687b60d65c6fbff7de78cfeed676fa37efb75effed979f5ceaec3cdefe7b4babee0f8a69e6f7de4ed8a5bbdafe8753ae8eef77cb363f7f7415bcfef79cfd35a7943e3b783fd2d9eb35ff6f7cd6b2b7cda77a7eefe6beff8725f1e7eb35dbd4f2b59e976768eaf7ff5e64f0f73fb2ccfd449ec7ebdfa6eff77333f5bfb7efcabe75beb7d2ff73e4b5ef1863f5a0333644d9f307f777fededc8199fd0eef6bbf5c1e7cf2afdfd9bf7f14a9028402211e018408583b00840108e73c8465ba3195b90118d983010307846765746889676f312e32302e3133856c696e7578000001a091a0f8b5831bdbffb860a79e04e92307a88aacdb97e1af9c99826690c90dc3fb83251f6506c48fb5a8c515ab7afc554408fa67b4251b9910545601d47524cd356d2c7a6cf23e7a857666a3ca20c7b26949815d00ad110a57486afb03ebbdc0e6ad6205efda248580eafff84c8402211dffa0c1b3a1b35c53d9860d1464d20138e6271602e00ea876757d7106016ce83466f38402211e00a029bf36156df8e525f809db876705baae274b69205fd5716448392648e0941c52800290f15f352f1012037a54e82bc7fcef239ba9bb867286089a287d100ecd737449b93ff0af15c13affebd5db2a6be4767192689e8bcc809b26b794d9a37468ec00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a024897fb02565f515fa9fbb541eae07a132473349842b34786a06ec2a0d6ea64ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942d4c407bbe49438ed859fe965b140dcf1aab71a9a0175af0ef466ba120d773ebb4e5cf28141d94efd6214e5bb9cde6ef206a3afbfda066cc81edf1fbd1f605d108d2b478fbe7bb0c38ee3e3e5650ae035efa563fd729a0e3431ac6ae4eee634fd6a1d6e45807789b94ea432bdf8f9f857545823798e824b901008e7ea3b3105f95d18ca860548c85a7efd518cfa69c238dbd4efebd9d241b25f1cc559715d455a3e533b036ad819aa6b19b695ea91c3b23cebd293dd0b2b6e0ec56458b681fe22f7d45eec13f82ae55b2eaf5fe7537677a8ab6641be7f43100c09eccb83e9a8fa79e8f2f853d47b34bdb194d8c61c8fb2e6f6af59c3ac658b8460f6bc24c028e2ac09b88ef42a9028cc03a3577c9af93d67beccf3771457b0bfa92d2112a9be46b607ebdc9e67a14dd0d6ebd1cf9c48b7738a67744b114f952d5a1227fc312292cce5ca1aea7c48a1830bbc5e00a95c934fbf350d5d69ea1ed3edfb3bd79b9c95528a33546f781dfebbc6056911153b0887ce359ef1c8ac9181a028402211e028408583b0083f9c3198465ba3198b90118d983010307846765746889676f312e32302e3132856c696e7578000001a091a0f8b5831bdbffb860a5654b7010dfdd178f3465135f42d28c9d435d60d0267f87b2581e1d7fafab606146fb70c620b1663b0d46e5d58ca1580913f76779e3c5ba65916db7cc73ccfb9a569e3165266c5ccf25240154aa60ff995327a2a8695a58d68b2105314ab370f84c8402211e00a029bf36156df8e525f809db876705baae274b69205fd5716448392648e0941c528402211e01a024897fb02565f515fa9fbb541eae07a132473349842b34786a06ec2a0d6ea64e801d548b699a7cee908420aac8d540a2de752823af731ec288b2774069730edecf3d4900535cf7714138d359177c9064e446a7730b9349b3d2ee0436b5072a855201a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510ffbb84111ab51df90eb2f90211a0890231389e1c4e6a2f6e5b8154ea372063ed7d917cf0d32d7a2cd21adfd06842a00ef48a4e0bae1cbb1a3caa52a05cd1bedf1e22dc50e680b85838b4c4157f06fda036e5ab2773e21147d9baff1b131278acc2c6d94fe9b23d9fcfd03723db7bc345a062e246491852309e16167a9d3bf7496bea6cf7fc68bdde6bac349afe27a228bba09bb79be4b97ec382e2f13c4e552e85c5e8712e4ce079a84a19aa5008200d5b76a0e731649692d47833e6cf7053d746ea42d495ba405c363e9b7d0c672c8c4481b9a0e9bc22e8fa15d085a68c3bd14b9a750d310e1680ac5bdfa386f850aaa67905b8a0c352465d5662ac5b77de54c34855ab9c4e808378ab1d645cf7a30a8cb51caf26a00f4cb91d858bb51b8a795863d9552e1f105f2e3fb37f1d161c1dae4b203a3c72a02e7905a411dbd014e64713312927471c4b1c3885fda3ed5888c0fb192e6de359a05e60aa49704b32fcbcd9543275600ba900547b31ddf446d55c527f09f0f5c6f4a08886a98f2e030a70ec24f9b1096b548005b64c88faf516361a2a694abff08ac7a0f072b67b389d8c065c6585b92a89bcbdb4440ae210060f7b98ac92d7b1e62f8ca0e8ee249f924ccd80781c6892e42a15c60da9175802153a0ac71650b02c13ee36a0a8632cd2f0beeb0f89b728d65d9ea803bdf0b12a5e3d27cbe5832e4ceff8735ba0b10c2c47b02cd583395fc5e70520bf57b97ea460f5fbf600049db152afa0ab4880f90211a00971b494845868a4a6f5a36939740537be16ccc185b7724bb249439267aaacc3a0ff26bff9727522f6773d888a48e2f444b020e62fce9bf0c6e15eafa0d7c3cb58a006aa21a0b04e596b5a4ebbb384309a489e876c1be7e7a2b02a584b4530d66925a03af99e922ded079114bf3a92f2a21d0a5dd131d15e0f3e01c6410974fbc3d8cca011114fc621c9378780c8ded766139c9c1c5f03a8de0747eb17bf337ea4a2ca2da0604f4775514cb56b34732652f20b49abd5c40ba4310353e3e0271a7194379e9fa00266443ed0582ea87a478be34336830356a001e40dc4a05d139348d794bc0ba0a0c8e7006ec197ab21c2409125cdcff2e78f29fea018eca902733c017f43ca794da0dcf51b76b1845f2b5bce3e5e2ecac30166b619ff1f18329ecfc49d1f3de50d06a037c89a9609e09d5b06e33b8abd35e3f9073bc6bced657355ff26a44a1fb0a361a08290bc67998f67791a82885a0cb0e81cac9f35e02388febf3952b7b5b79f8885a00f172f431296d1e299667720093d4d3ccd4ec7aeec24241ccdea49ea1688646ba021de7fd2dc90ac8bb698c0888ec4ff9c19f5e5748d46b49dd7238da60e7fc3c6a018c43df08c3e25d13db0b22ee521f3f450aca517916b5cd5219c86b49e49a044a00b8131712251baad84b82f2a44b8a4868ac8d87f03fb631130fce4be948ed9c1a068aaddcd50b8e792c89aecebcc859ec916ed530162583515aa71815f8542b4e180f90211a0c14274d28a2e70b696f18013ed25d6dbad53e4f055cc95d9a831c025c2ed9b01a0632636410cd51a3c53b184462e1e407a0422ec61d24118ffbf9aad2e0158d97aa016c98b9e76bb41d55d32c15e53ff870dce6db42be5e31d669c10f60b70409912a01400aa2f7e63dfa22e66c1096a7032502c24b261a52074dcdbaf7672d411c163a086ce70144b17c65c8a205f3dfd182959f0b1fd7f90143ad50e6999752832694ba0f8d20b759725fe897eb1f8987aff3e33e2bb00f32ebd4ccf2068a3fc89ca6080a044de2aff10255376ed36b22eff5590eb58d3ee54d0e4cc7eca4d22ee11bf7387a03b8d65e333aa13f8afa5982868e7f7890ba9e9d1e71f57b6d3a7ecee4482d028a07983b553b56cdc0305676f9622ff64df4ef45f1400af3a94ad08cdfa43c8a6f6a09bfea18d16df95e1dc70ce655d8bd283c900157317ac53c05931096c80967c93a0df5c3ffdaab83f24dc1c21b63a655880aaba83e13ba3037db17f53dab3ecd908a03e664ae0cd067a6ad7aaed8ba647c34e2cffde9104cf9d385f302c7fcd714f85a012e7260db92227621f4ed41a8e50582cfef95cbad9d1b22ff14b82d3c59d9241a0a42731a74edae14df8c52c748eefa4dc148b679ff88e26ece01a753247875154a0a9bf2ef8979a58da04857064c92f0ca860c12e1e1739a419faa1a7a179e6a575a0da31d47321bec6cec888e06e9182d2b579b470e53fdb241f1d7c78f88c65133f80f90211a07cd4b1279b228ef40481922604a05d005cf3e596efbb7eecc920460725ffc958a04d0eb9ce763d8b0bd7d77eb2c450b1d1a68fa9d4a39f74fca416ae8b021dc252a0c8d17bafc04d0578123e28fe318c024cd8ffc2919906c9a0827f1e790c63ca36a03ec45bc4463a145cf8c75f30f706e244a745a1b27283c92dd8e29bc787fabeeba041e3e5a0474e922690d384c4ab603cf6cae1c5333510c5489a0b9cebdf9eb16da0872a5c56d4ddcfab1473aa4b5187aec0cd9ad6be7316293ed93e330649e6948aa033e7f70da3e2514734dfd9f6e22139c326c409ef5a098342d0ca117baae919a4a09822c694761ebd9436d546b74cb8a3c333887e3794521ac7ea5fa7f130306265a08f93244365f1bbd3d34190af7531cf9eb3bc752f4a7b37e2454811675098be24a0329fd3766ca5e0ead8ad587c20aac5d344426a175907f80b2ed4f3eda8001873a0704b7adbf076be42c914ebb93045d9dba99269d719e72f716e5c82e1c4d30ed6a05827484fc8250b11323578d86af3b2d98db47949bd7fc670fe62ac6d8b2b29dca0c50f5090c95cf05867a259e409440a47bb221fc0ca50765ab452a3b448fa68dfa0ea739dbb4d387dfb6f0aa8f13a8eeae6aef55b21512cb046f5cf6bf142a61d79a02fd141d9061f06e999c896bbc7b1d4d652be24a710c4893e9d7fe7aa30f7cfeea0135be94cdf13c38d956f6e782ac6ace9b8cc40305249ac24dee470a8236e7e1280f90211a08d19750aa033c3351c90890a8f3ce2bde5f8be2b419c6f45115d5e6fa822ee47a0af80bd31da73dd38aa307ddaf4a3a4967139569111706d42284c59fd65e962c8a0feadc5dfc37b565bf229e9c73931d9f2274a762ccd3fad295ec327c6afef9525a0974634e6d38bbff1b17032a6566dbb3ff4d964ddf8fd9461cc13be120a4c79eea08d665f3fffbb6db4768102cb4c238b7082ea97f148ebe52a4a7e2aba26c7c537a0d9f11599f8cd8e41ea2799bc67598f702cf749be0a8990f096f8047fba2839b0a09be08e8044dc3057d056efbf1418467b516c8eb78b6d3c04aa69a7da735886a7a0f098ba0d8d2aa43642190af04c3fa97ecd8a2fdbeb5d6a2fa8eb1312176c763aa0a5aee8d8da8b6c01810834dee37121817b4a6889237bc060c1b78dae010ccb6da0495ff86cf6a6a9d9b043c204db77369e9e9d9767d6af4d963c05468983d12a2ba0a8e2263e1242397424b80e4e5303d95c34484426f63348c4346bc7d7878a8cbda02d6d70eda441d1c2383000a093400ade51ac7a04abc1aa99a7ce7b1624cb731ba0d6e684d598642afd2d7934c57123128ba3485dd00862b738e8f18355286f7423a0e09050c854d7a0d5bfcdd14f07043fed81662126e2701a4566c1d7a261900c71a03ac1f69f8e20a8792ea98d671e979a20b51ed4b37b40e2671dc05dc4d6653ce7a0598310e43fc8ee41ddd015d5d2764c7cd4959840260cfa7cef41dff52ac51db980f90211a0f87b60a82c2c32d5439e3199ad0c3a009a7f5474a027dac454b09effadd1fbefa016bb48376076116f468f16394fc6898356d00b458ed14b901461d1afafc89e65a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa042fe91ec49a406bb4a35b05a7fc518b915550848ba48afdea839969737e94d19a0fb5a2ac85aa55665e6a21b4d77a80693cfa450ad3db8e22963f12740f79e948ba0a32564adebb5029e48a91c8f6a90d04de2d3042b4a44f20e347bd68a26ab0cdda026c57b9b5218aee794dc9b3f90935ff1374ede5b73847c902ca61a1c41105e9aa02b22a7bb0d1b84b9d89fbfc571f0c4122bb12add28e944b047e40323fbbc33bda08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca08987636c0999e2eb3d052f145cd6b23f50946f6d737da20b5a7e2e1a8dc91c97a0e4fc7281b24a4a9d96dd4af6804d6276bc1c176d8e34979da2e7140310e66adaa06cf03705b25b817df44e3bc2122f8f49ca8aa80f32e7cfc5ed69f6c37ff49c2ea0dc66c764a34bf9f1c62917dbfcd1b930fd9b9c4379d520104519ab3e80f05265a004c43c3abc9e1ee7c131611fb29bf3e55705b91f687b5b30bdb6c5fccb431232a0dc32b4bb85eb8facf38af40cd4f77d9159f4723c939ac466e106a6d3c7535847a060dfd3aff904b5bb6d5f2e37695e05c9b935fab7888bc88486f6e811f606e20080f9015180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a06efa682f711f1d9e189193bd4248884cecfa463028d015e6086a7de0a0889b0780a049ba777ae33a75e8c0c7bd07597d6e6fb43624537a579b9a06b20c89d6918b2980e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252244685b1ded8013785d6623cc18d214320b6bb647598a60f82a7bcf74b4cb053b9bfe83d0ed02a84ebb10865dfdd8e26e7535c43a1cccd268e860f502216b379dfc9971d358224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d7886948522449bb832254baf4e8b4cc26bd2b52b31389b56e98bab764a39ff81dad720d5691b852898041a3842e09ecbac8025812d51b32223d8420e6ae51a01582220a10f7722de67c12244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244ce2fd7544e0b2cc94692d4a704debef7bcb61328b64abe25614c9cfd32e456b4d521f29c8357f4af4606978296c9be93494072ac05fa86e3d27cc8d66e65000f8ba33fbb2244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a44685b1ded8013785d6623cc18d214320b6bb647598a60f82a7bcf74b4cb053b9bfe83d0ed02a84ebb10865dfdd8e26e7535c43a1cccd268e860f502216b379dfc9971d3582a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a449bb832254baf4e8b4cc26bd2b52b31389b56e98bab764a39ff81dad720d5691b852898041a3842e09ecbac8025812d51b32223d8420e6ae51a01582220a10f7722de67c12a449f8ccdafcc39f3c7d6ebf637c9151673cbc36b888819ec5ec3e97e1f03bbb4bb6055c7a5feac8f4f259df58349a32bb5cb377e2cb1f362b77f1dd398cfd3e9dba46138c32a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44ee01c3b1283aa067c58eab4709f85e99d46de5fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let height = 35724800;
        let trusted_height = 35724799;
        let trusted_current_validator_hash =
            hex!("97e642190471429a60b6964c475919444b7c9f8972a33507c30bd8d2c728745e");
        let trusted_previous_validator_hash =
            hex!("1097f9094a26384a86fda6f22e5da7be996beab06fdb8eb865f5fd2b90b6f39e");
        let new_current_validator_hash =
            hex!("732ae226da9beae0b00a2eec692956f0760b237f30f7b7e8ead93d92de794621");
        let new_previous_validator_hash =
            hex!("97e642190471429a60b6964c475919444b7c9f8972a33507c30bd8d2c728745e");
        do_test_success_update_state(
            header,
            height,
            trusted_height,
            trusted_current_validator_hash,
            trusted_previous_validator_hash,
            new_current_validator_hash,
            new_previous_validator_hash,
            56,
        )
    }

    #[test]
    fn test_success_update_state_non_neighboring_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212d15b0adf0a0adc0af90559a01b8c590cd6b9bcf6c24e47e5f6468083f6093d05f9cc6a3f45c0e61a7989914ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941284214b9b9c85549ab3d2b972df0deef66ac2c9a03508e22b6e7dd679e544f7badb659cd936e1722f9a91136e800681d588b886aca01aa0294d38be68038c13ca83d122e765b2714e3cf5a7c8b382eab64f009be8eaa026033fa1fdf7e559f128b7380b369d908261c092e97040cd938d0c2cc83c8d52b90100000448000000b680400000c0c00010000280440000920200002040210200009000015e2004022110000830000800100000001222041000004000800040ac100004c0003004102013000540080008820021180000100482004041102000001c00100c68200202009509421005288a684028202400000408912000403080000c000040481c000c80141840181c20001004102084e02800200a040000880c18802006028010c000062808040a2022023082410200880080104a40e00011000000021410981200100a8000026900081200002000808004800420811049ea00206000121002c210000002491000941000110000249000809900084006210020000a00028402620fc884042c1d8083303e3c84663394e3b90337d883010406846765746888676f312e32312e39856c696e7578000000821df8b90808265da01e1a65d62b903c7b34c08cb389bf3d9996f763f030b1adcfb369c5a5df4a18e1529baffe7feaec66db3dbd1bc06810f7f6f88b7be6645418a7e2a2a3f40514c21284214b9b9c85549ab3d2b972df0deef66ac2c98e82934ca974fdcd97f3309de967d3c9c43fa711a8d673af5d75465844bf8969c8d1948d903748ac7b8b1720fa64e50c35552c16704d214347f29fa77f77da6d75d7c752b742ad4855bae330426b823e742da31f816cc83bc16d69a9134be0cfb4a1d17ec34f1b5b32d5c20440b8536b1e88f0f240d3256eb0babe89f0ea54edaa398513136612f5a334b49d766ebe3eb9f6bdc163bd2c19aa7e8cee1667851ae0c1651f01c4cf7cf2cfcf8475bff3e99cab25b05631472d76d76ee8823de52a1a431884c2ca930c5e72bff3803af79641cf964cc001671017f0b680f93b7dde085b24bbc67b2a562a216f903ac878c5477641328172a353f1e493cf7f5f2cf1aec83bf0c74df566a41aa7ed65ea84ea99e3849ef31887c0f880a0feb92f356f58fbd023a82f5311fc87a5883a662e9ebbbefc90bf13aa533c2438a4113804bf980a75ecd1309ea12fa2ed87a8744fbfc9b863d589037a9ace3b590165ea1c0c5ac72bf600b7c88c1e435f41932c1132aae1bfa0bb68e46b96ccb12c3415e4d82af717d8f474cf03cceff28abc65c9cbae594f725c80e12d96c9b86c3400e529bfe184056e257c07940bb664636f689e8d2027c834681f8f878b73445261034e946bb2d901b4b878f8b381fbb860851066357eff502b847239dce4def537c09981995b09a20b0332a5931b6a80a0756929d82d67ada1699558c423a5108b0754fc4a8729fd2967822ee274fecd8742703f1e758c0c25aa65667ac33ca73a09dacf4ffeed749d956d6b438a65fe35f84c8402620fc6a055a683a5f4aec18ad180c783416fa6064fd77d12dd9cce6aa4e2d21814a1358b8402620fc7a01b8c590cd6b9bcf6c24e47e5f6468083f6093d05f9cc6a3f45c0e61a7989914c80ac0efe500470240a4e493ae2a67a28f2974da7a8b00ef170fc1d2357732a713d15528f7773b127095705a9d064c155484a7e3e8ccefefbcd1cacc960b3a0fe5f00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a00675a9943e5eee827641ecf76ccdca86c00760201e79454d7d70bf1d1229f4e4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479435552c16704d214347f29fa77f77da6d75d7c752a0f88cae15732bc072d88e3266e79c63ace19f6158d861b5a1527eecea8b3a0c90a0805f0392fd4fe5f40410188ae1823170f330fcbd460029d64100fb762c18db22a068061db6f72b36216ac8a6d4e7ade646d0481a5e58a1d446699f73f0000c65beb901000200000000000008100000400028002100000000101280100000602202000080440850000800001001020001000091010090200a10040008009012000080600042005010001000000010200880020010221000a0000208004a0c88000102140000080061090200800044000000000000080000000008088002090010040200040840000980000008000000000104000000100c200840100000000086001000200400000000008020084009000200204002800000000080008000920c0100000004880a0a0000004001810000000120124000009204080080001040c20000a000000030401000000201004004020001820000c00000000400480008000100a000028402620fc984042c1d80831a1f2484663394e6b90116d883010405846765746888676f312e32312e39856c696e7578000000821df8b9f8b381fbb86091ba1e6cf213db9c2384a8b80d1a61adeca1222451ad44989a3a4353c926cde613198ca3031c6b7c7988b0302c51f2bc1762f889d44c27476f73339069a6aa0b5fce63de2c6e847ee07c01620e47d27d090277ce3069e61a8e0e5dc75e7b6c02f84c8402620fc7a01b8c590cd6b9bcf6c24e47e5f6468083f6093d05f9cc6a3f45c0e61a7989914c8402620fc8a00675a9943e5eee827641ecf76ccdca86c00760201e79454d7d70bf1d1229f4e480899ca0f597006047cc915ce49e35b70eefe652a4f46d2cf8f9954323b29dc13a07ebbdc07dfa4f17138db9af8611fe9a98d289df90b46aacc8d86e6f39c7528e00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a06f8122b4b7c614859a61d8e12f236efc07d92370c52e9f3f8de48bc4c4c3f76aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479440d3256eb0babe89f0ea54edaa398513136612f5a01d6899d6d2e0f411288f145754d9672ce2881c44d3e9a25a6a33d5f625ec608ca09ef5f809e4322bb7ac0df0c4b4ce82d4fea1e31832734ed2286e1bbf3bcf5967a04f4875ba4450b51981ced70f5cb8ecfcb4f402a2ecca8f038ce9340431ba6677b90100100800080000000008000160000000240000010190000800000040000000008000081421000000100002001101009800001410120000000000001a0000a11200002030300820000200001008002000002010000000000000c000508001101600000800200a02009000010000000148c2080000000004089000080890420000000042000800000000100000011010001001000c200c000200442000801810102f060000000006a02808440000028000040001008800000018000082000000000204414802000089000021400010428000008000840280010100104142000020000010108a08040800118400060000010020208002201000024000100000180000028402620fca840427f164831ba49084663394e9b90116d883010405846765746888676f312e32312e35856c696e7578000000821df8b9f8b381fbb860ae5cfdf126fe914ba373cc010e894bdc02c34c113feaa7bf6e027879725858c3aa8740b6abb90f1dc389003dae1eb30d11aaead3c1df95d86bfe201cf0c5a285dd915f13a712abd523322712c42b8195c6cab1b5b0314375c059f48b8b79c8e4f84c8402620fc8a00675a9943e5eee827641ecf76ccdca86c00760201e79454d7d70bf1d1229f4e48402620fc9a06f8122b4b7c614859a61d8e12f236efc07d92370c52e9f3f8de48bc4c4c3f76a80bf2db108411fe95e684c82f738764633a2d29253d20c1832b7189b7a52f4c7ab75224c2bc89d3d1765b1aea4a347f2526cf24c4518ce3eae863383938cd651a001a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a0b8f6e83d72a579037a1747385d006303baecd2f9122ea38d7d7caeae4322fafaa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479476d76ee8823de52a1a431884c2ca930c5e72bff3a090533b33c3cc5cfecbd33918e04cc12957a3cf6a5844e65a0ca4f2ade2994b3ca0e6977483ef89448a9e5565ceff05271fd57f2ba905f9caad339902e605fc8db8a0465d7a4ebdc6f41f40124db3193e5a0565e6a877854715c5811eb143d1d5f392b9010002801044080080006022024040a0002000a840003012002810184001000409924008152008200011040240012c00100120102002000000200100020000a4702006466030020000000001000c00008000a0180000000000804241102800111710100c46a00a02009500060004288008400c000400081808900001045400020c400240001c0000000000000ab000081008001c0ea028028002042040800810202006480080400006380840100002001402010000c00000000002a08311208022021400981220004881000300c002035001000080808ccc0324001040420000600012383086100002080941c204000411810400800000c020004c08080080480209028402620fcb84042c1954832408c484663394ecb90116d883010405846765746888676f312e32312e39856c696e7578000000821df8b9f8b381fbb860ac51bacb0156bbd71fe9d754817bcd1ef367cd0a6ca2d719fd1f9294164e9ea536937167df9370e7e4271846d099f1c01785e38478fca04f68559d2740447cdfc8f8e1d9bfea1ad6d331b13c63d133504203d7b6197e59837128b91b568c302cf84c8402620fc9a06f8122b4b7c614859a61d8e12f236efc07d92370c52e9f3f8de48bc4c4c3f76a8402620fcaa0b8f6e83d72a579037a1747385d006303baecd2f9122ea38d7d7caeae4322fafa80995177c05ae18a7afb72a5a5b870aa4cec13dd3bec378bd0bdd45c8b32ff9d94379d0649899e58045bd798c90c83f068c6180ac3be527f5264fd1fa40d5f3f7f00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a0c1828f9fa73b74d490c01682f5e7851683736d6d38437034b118ecd99aac908ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947f5f2cf1aec83bf0c74df566a41aa7ed65ea84eaa0909eadb50d8d80fed8719a8008f9a96a65105c9f9adf5f09583df44903455d08a07fa76502e2d2fad4544c010c2cb4719b07845b4ade4c57c05c194dbe35f27990a06c6141cf0821319308c5b281ebb93512f27f384d9d039387d765fa27ce7f5ab1b90100020000000004081820000040000000c400000202800200000008400241000080c0001c0000220050000000000200100000000082080000080000100000b064000000201000000011000010080200000020100000240a0400c000000080041700000804200002208000401000085000000a00000000080890000010140000080000400a0800080000000000040082000100000e2018000000000004c208100260060000040000003108081000020000400000004000000000200000200000030004000802001000004000000040101008020000000c06200000584002000020000018000010000000011100040000110280009000008080084400000004090000028402620fcc84042c1d80831f9f5d84663394efb90116d883010405846765746888676f312e32312e39856c696e7578000000821df8b9f8b381fbb860965d6d03c0493b4b7a3cf91fdbe7d114ebd38ce476e1bf47f1d1a55a8286408e61d2fedaac5e6c9b577f808ddeca453619c2fa244c4c8d0c521caf5148b532bcc376df1e5195419b11a350b03b596bbda029f1b074c42a3e9ce26d676c708c3ef84c8402620fcaa0b8f6e83d72a579037a1747385d006303baecd2f9122ea38d7d7caeae4322fafa8402620fcba0c1828f9fa73b74d490c01682f5e7851683736d6d38437034b118ecd99aac908b80e1175bb3858b24abde91024c935edf639b17cd3d48a67110b486064b018cc30273e32fc65969bdfaa4f6c72e0ead81230fa220f767d21f0a434ba82d9d5f6fcd01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a09c7cfa55ae4789be64a696d357083683dcbc0429843811c125087ffd383311b2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794f474cf03cceff28abc65c9cbae594f725c80e12da00e783cf76ba10af8b476c2af6f0099182dc3d8891e6bfe8ccfbd4df4df9e5725a05943a3797fc784ab2a933a7e8cf5502c66932b4d565bf39673d8c84a97e7c163a0887d4fd11bac9b67f2a36358099ecfb8a3777074a31a1b01b0a2ddaa1621e312b9010000010000000080040002824000000024000000001800000000000000002800a0002810400000001004020001084090010094204a010004000000020000a0600002000030000020080800000c8800080020100001000000044200000804405400000802200a02808000040000000008400800000000802000100008100000040001000008000000000000000000a0100000000420080000000008100010100021060000000004842008400800020080040000400840088000000002000000000004102802000088000001200000000020000280040008002000104062004020008010108000000000010040040001010000008000000000004800080008000000018402620fcd84042c1d808310765984663394f2b90116d883010405846765746888676f312e32312e36856c696e7578000000821df8b9f8b381fbb8608ce86edf055073ed3657cb976abaaad5fd17879de455c0261f75a68f1fece6134ccbbad1adb809ce0c8e7b50249422c212357367f0e2feca28deb104d6bbfa1a2dd080a66914b21756e2198cf1c52f50ad6edcc07ec72818f917e9d7111a6574f84c8402620fcba0c1828f9fa73b74d490c01682f5e7851683736d6d38437034b118ecd99aac908b8402620fcca09c7cfa55ae4789be64a696d357083683dcbc0429843811c125087ffd383311b280f18262798880d70059d643979022a2b63e4198d03f7b42b1b2ae3750a00ad54632f0755542d43c630c263fefea44700a9c2f5780aacb850a98fb22816843643701a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a0fe3e114a9b8862d981e404b7f83f43330e8a6a1d6f853b450ba8f358d8e594aea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794980a75ecd1309ea12fa2ed87a8744fbfc9b863d5a020d51c5c97ddeaa92872cb51e57cf30cebf201e4455a7628909a944a153fdd29a08498edb273bef28ea8bfd2cbe9a99e2c94eac71fd9752a46178549e43b3dbb76a0af8c731b24f09013ae128678c593b89c686e5936789049da0a20a421f883e50bb9010012000008000800880000006000001000000000010002808010006006000800a200005c0000220010001800000000110100100102000000000009182000a06000020030380a0000008110000800000000a01000010002020040000000a4001400000880300286009880441010082008600c000000000838910000009008000800004200081000000c000000001000001011000c200a00000a040040c108100020060000040004006808001840020040c000000100000000010000901200c000080404681200100100000000000010000020400000041c000000104002000020001018084010010009011540064008110220009000001000014000980008080000028402620fce84042c1d80831f23d184663394f5b90116d883010405846765746888676f312e32312e39856c696e7578000000821df8b9f8b381f7b8608339e352db1dfd13827e415235e7ad9653cd14056bd7b78e93e09c86c36679ae02e13a2ec4aa1d8e2546fb5655f621d6041c1b9aa04ce18b41b7273fbab06eea3aead2ab3c6bdc791bb6268c781267b4ec81143312f419a48422eab7e7d8f1ebf84c8402620fcca09c7cfa55ae4789be64a696d357083683dcbc0429843811c125087ffd383311b28402620fcda0fe3e114a9b8862d981e404b7f83f43330e8a6a1d6f853b450ba8f358d8e594ae80b25e98a9d4d947ccedfd894f38dae23c09a3f30ea5b513470d75eac608d15b233c39278b14601bcd777c2f0c61fba173b2189614ff7ab761ec48e03ae2894eed00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42180800abe060abb06f90338a0ad80590a86e436e79aaa961dccc29d85d1304853ded12197ae2dffd42e75fa18a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347941284214b9b9c85549ab3d2b972df0deef66ac2c9a007e946b785a9637930533c6df8d79bb93184e47d65d28f7854d8c8ce16c63c42a015de33fa37a8bafb7578c335909aeff2b2b679997e548ee1a8d9f47a892ab1a7a02ced64c3059d0e81f236cdddfe8d034d05a08e1fe845ba32b4234d5ba8a377d6b901000000200400082008c2000a401000002000200a00103200000000502340000080002c142000000010002300818280140080100002400408000010120000a03000040000108400000000011108020012002210000020020408c80a100000171600020800200e02008001e00001200008001a0001000008089000081014000002040040000800000000000000000102000000000460080000000000088108904866060080800004006008400200060000400080008000900000a000820800020102040008020080000001850008400200004200009004800080111040424800a0000018204a5000020041000015000001020000810000202008440000000000c000018402620fcf84042c1d80831bb60084663394f8b90116d883010406846765746888676f312e32312e39856c696e7578000000821df8b9f8b381f7b8608e8cfe0b055b18d322025f0837aba5e1928a13f666255b83cf0529ed987b9b4e449d6248796bf8a351bf21cbeb4d869b14cfe57601beae23fed96172aaf53b42c247caacd125e363c7d4a36497c20523a72100fc4bc1a8f1db3ef66f882b1b84f84c8402620fcda0fe3e114a9b8862d981e404b7f83f43330e8a6a1d6f853b450ba8f358d8e594ae8402620fcea0ad80590a86e436e79aaa961dccc29d85d1304853ded12197ae2dffd42e75fa18805a390422f87c05ce81fad47bcbabb415c9bec71cdf4d6b8878409322a810d8567ef061cec5384ec4e0a754413ce28e6fdd24f54e84706337e863fef60b2489c100a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080120510b89c88131abe1af90d3bf90211a05d54f311542dc86508c3950fe9fd0e42666c4b0d2da357bf0ff5256206c4f499a0de4549196246f89565153fe5c293bd86825c81bebcaf5d863bc20db5b80f39c1a04260cf26a849cc8ae7d9e9490a0f3cae30ddb388a52bbb4381b648c6927f5d02a01043cbea73d2e4dad6a3021744ae80ecceee3fda23997f7e5a56d30721d6a89da0016bc5f3d3af4289603df49b9156999c4b3fab779399bba9dbb8d98a7d5fff36a09f7ae1ed754c036e23f8cee8168086eb854e9a74e50f80fe6eeedc06652d65a4a0aa0c44232305f2d9c73f4198c114a79f935d4f15479dcd8d61ab3fe5821608c3a0b2afddeb92bff5ff52f0d7d432e3b5e2c777988181eef046d4026e23a28a15fba02a6282e9d54cbe11efd2a4a36c899aeaa7cf7604c6c1d496d4ec36b26870d945a0d7c965d118cacf4d7282ee52216d42b231163efbb82fafc36bf6dccc2ace3b53a0e05dadba137f39580b713d54564bb2ccb48a4a4e882ac673aa972f6b4a7e2c84a0e35f8dffad08d4c9df98129ee14a657c0076c7e5ed00fea40d7bf4f9ae07c2c4a04a9dc6bc9c6a276620ccc29879f3e4195951f720322b72f3925c5862c5972487a06a7b7c9de98a1f4d36cf112f45b71e797694ed5b0c8ffcdcea26ed337bcea62ca0904b2f7a0c508f1876c1ffbba7832ef5babe8218fb7ac12d0f9bf4245b356a39a0bc5622b08b6882c64c3fd5ca4feb7cbe7845c911b3518874784719dac87bf31380f90211a0ed46c5f969903bd014b453e23bf036a0807d974ac245d974bea3edbfab8998f7a0fbe185c3ad730c361d61adafbf283c230a9e04a6971a5693a58b95d54a91dc18a01c49f9acbb2ef6407d5d88ad62c7e41c0ae4e1a86453d107f8b88e366e6f1f27a07f263e0e9ae17cbc40f87c3ce1249a552a18c5dc0b7fe42e43454663ac9d4a10a0ef16b26fa26244501acfcc480235d9fd3859b0511b1d840cb3960143eac49e4ea05e19c98be009508b8132d6bc03ce932ae80c584fed6c8b66690f51b6706c6110a02699c04fa558d4cf31a72eccdbd6c9b85921b18e92be8013b16bbbb0e0243d95a0bf06ce588155b0a5b8dd34eeb8b34d1ab6698da02bbd47b8df956f3f8f958f51a0105ad803a3be71de2802142849753f93fe3445762ccdccda5baafb2c350fe8ffa06e725a7130ddbff26e37c27c25830b6c3fac3575371cd00d26e799c30cfc61e5a045a5861fe345d073abd640549c0bc754f98a15f1349dc94ccaf8e366d747e800a01fa1a61b7b9716a711f42192e558ba2fcf059d8b87ad67cb4c73aa65bc918226a0e3b653f8469bce44931ae9a2f88c3ae385b70bae52b43902b618a0e29694dd8ca09f207e2e88901b54fb464545a33764841152a2669f6668610bc3fa10d5cfc2bba00393790748f68bcffb6f9e01a409b9d1e691406b635a1cca73ae061813ac4d5ba0c3f4178174074d467324173d8436674ce6c69fa7c49a4337a000635fb04dbf2380f90211a079c04022f20db8c5fcf561e1956bfe73e94c6e4cb2655ff506c2e298f1ab8f4da0c0c9908e024252617bb968a090881f478cf2cedee6762524d4b2d3521fce7b30a09a502add7d10c7817db9157721c4b03ff3327415d6d3b0307b11efa07a2ca300a0911e146a2367ecc6ea7dd6c2547ac9df60ead03cd1d14ddb3350b3968c7fca53a05cd154e740f91a9fc1b2b780c47cc5f525efab2e7c7c36248a2833a99206f291a03761f080edb655d24c234da08813efc750a093ea75e9603d558dd2889e254363a0035ad7eda8fb804cc3b2779b0f3c40e67f5c7fef6b354878cc659bb76c02871ea089848d6e6e0132be50e1428656da8fadda12cb411681a9cab7d5d9371650f2e3a054ab857606b93e77c264d3ae1c75bb7d8e532a75823fa0646934c6b07587d97da04303a53d5b1cf36d7ca5b3a35ff11b210b7fab8f2bea560fee8e1dc49863af08a083b73ad7bf82dc689745a5bd39837939169c725f44b3bbe5c2b9470c557cb6c1a01eb14803b41ee30b3d9256decc6b02f7b4eac0cba1cf60c7e806aa145dc95c3fa00f46a8879a158446fd5281f67942859516c094afff5c862d7925e28e0255dc1aa0a88775f84e8812564ca66ffdfc617993b642e48863299520f34c9e4f2b394b24a065a8676f56698d3c88c8360411a1b5d89cbdf44cef98a51fe1b761ed82177bdda0e9216b548ea5ad232ccea4285597ba3345a53d39fcd61de9546c24725edac4c980f90211a0fd00080f96539f8eb5a2b403c9594f7bbf1a9a773c9a4430d86ee7f4fc67f041a083d0f27ec441ee36c6b0479c30d213d373edacc372fc3818fc98eac3c53da4d9a09eefca974fe868babfc32bf6e1449d97d14a891e3b10bbe54f64e00a0b5dcca1a0ad7b3367ca39009b957a1825269c78ca3af9a2a87c43894fb8bb9ec165d7a4bea07b68db0a8ff70d3557ae4c04b964de0fb67e3c340f3649c0af4bf79b86e73be1a02af8fdf09ff77e7f4d0e325050a8f293c08d2cb328f8d3da7e083a7d48924224a032a90f4a4456c9a1cefc92ea7026d74d9c1c5117e8b7d405e9d9440a8edfefbba03c40b1884e0810d2d3579d8be5483a651ae4ea3041f484ddef2f0ad5a70efc06a06c34468de46e1c6fd59005d0201b3de36cab1a04daf1b42073e91fe35cac978ea05901b53bc10fe26bfa1936e1ba5a334d168558454429aecd803d3e63304984dda08e3a481bb8b089125b4e820bc9e59c606c47631394830b9b37c06c77110bc512a06411f9d1b96b36d413236b20ecaa77fef4bf17c023b6a0feb143a7dfd529053da0c388a4b630d106f22778df9782863b29cc712d25423c704117a9cd46190d55a6a0c3260e27d68de22e8dd36e2a15055e3f9cc0a1503510f8352be2458ce2849cf8a000d1dc7f94ab884d393c18ad9816d364c001e8ed29b5339d7d673d05d8cf8c18a0cc90581b3014a0af5d5a263a6581f442d75cccfce15f6da447c30aa3eee35adc80f90211a0f4f253a2981255c3c0c2b023a074cf35ee982c4709fe56d3cfbcc0d2d3e9e060a0c97e5c55396e530fb20bab042aabdf2883db66f41abb6c71f8eefdae67334800a006d2ac360ebe8eb14a59e2cccd35c3a23d9c559f183102ebdb3db068fdf6a634a03a78bec1492adf068ece5e9820d72df85d2e0b2b992f0cacb7198fc956473d94a0eecba4d8055f6358c4ed0989fbf575de5f137c4ffc73a53ade1d708c45641131a0eee901dcdf7b3b76f230c684200e990fc2284b3a3cac8156795643a8bf45f543a0c679d68e57dd545e7489f10898128a6a90ad7df29d3380ea3fa2c8d036a714c3a063062d6a6c1cfe1efff0e6965a65446b61982e763eb36652e1423df1fad08643a0d6c8ae23af8ad991e84c43f69bf280c54fc3a731b210bd60f5b8f39043480017a04614a62c039ff880d7c65c891e6fc6c55bf81bddadb42b5171a8d07f7218d7c2a0bfec07e9660db8afc02cd6cc2524246febc098f596a717190d1ef155317ce046a02aec38d6659b1b72f03b7b80e078dbc40650cea494f56606154538491df2598ea0c75fdcc0ec88840ac16c38f4a5902dc1e87d704cfdcec825b0aeee25fac08c32a0e09b0acd86da73ca9edd0ed45f52e970c710860aced6d2e1bb3617d45d1f1cc2a0bd67f755acb481bd586d2adae80b8155e8c887452ff964c8dd0ac888032b7d1ca04f03b5b8ef01c49629b79e51438d92a2dd9a490508152a96787ea1c39e1358e180f901b1a0b253f4d804466eedf2500f7c56b7b5c81937fd8547fbe942756bf1c2974245b9a0dfb6b4a54ee26fb0acc8a98e28efc6a9bef48610921ed4c5ddad4a6770ec413780a0e5b8323277c3cd8b0da5297fc709533d25bc28964698a6f2cbc4ba80c4c474c880a0ad4e25adf77388513a19b6e66f340845f4da575e05cbb41ec3ccacc962beb934a0ec3b2876d5a7b8fb4c959b2e2efd9a3fee75ee4e65da5438010367610ca50ccca0316db872ded9164c79a846190e57eb2c3a4379087798b8e1220b3cc5ff5aea06a05ad6bcb5a22ccc01a7b218c06c217b5c6f6a54cd77dbf3385422f37c3a5bbdc4a039d08aa5ea4684c934cd1911177ebea1f2f3438d891da946a0396ac10b663b1ea0c73d499a0e4709723af701832cc2e07949df500d5a817709746c124757f2a46d80a07967cd6ca41b76eceb64c5373d85399a380af1d1eae78f56a33a149677398df3a0753f05888f5454aba005e67e1061a0bbb982c308cf90a89746abebc76f640d44a01eba4f5159fcb36c5bde7933e2632b0923167fad080618e90b90e98f450e0673a0dc9282be875f1e21a4245c23816f7c36bfaee11d34c472c29ae4576985f2e9e880f8b180a0f53d8c2cc17264e3f43339e6390b3de4123e0d3014e2437d51e9527d32531dbba00cbb4e2b6e1f2b59fb98c96cd2ee4a0a9994e91d18564b8289c5dbf42d653e6a80a0585dc8b79c33d7f248c845ac6c35ea102dc2fd2870e4e96ae7891ea6093b3e6880808080808080a05b8b9aed0df2c69df192889f2a5c791f16590efae13338ab7279ea1bab2fd0b38080a07308e7b9a6597a64d45bafaf4b3a2a4525895d77c7d8c146ef7720f5c693f7b180f86e9d30e1120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84ef84c588823d85d5096750e00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470224408265da01e1a65d62b903c7b34c08cb389bf3d9996f763f030b1adcfb369c5a5df4a18e1529baffe7feaec66db3dbd1bc06810f7f6f88b7be6645418a7e2a2a3f40514c222441284214b9b9c85549ab3d2b972df0deef66ac2c98e82934ca974fdcd97f3309de967d3c9c43fa711a8d673af5d75465844bf8969c8d1948d903748ac7b8b1720fa64e50c224440d3256eb0babe89f0ea54edaa398513136612f5a334b49d766ebe3eb9f6bdc163bd2c19aa7e8cee1667851ae0c1651f01c4cf7cf2cfcf8475bff3e99cab25b05631472d224476d76ee8823de52a1a431884c2ca930c5e72bff3803af79641cf964cc001671017f0b680f93b7dde085b24bbc67b2a562a216f903ac878c5477641328172a353f1e493cf22447f5f2cf1aec83bf0c74df566a41aa7ed65ea84ea99e3849ef31887c0f880a0feb92f356f58fbd023a82f5311fc87a5883a662e9ebbbefc90bf13aa533c2438a4113804bf2244980a75ecd1309ea12fa2ed87a8744fbfc9b863d589037a9ace3b590165ea1c0c5ac72bf600b7c88c1e435f41932c1132aae1bfa0bb68e46b96ccb12c3415e4d82af717d82244b71b214cb885500844365e95cd9942c7276e7fd8a2750ec6dded3dcdc2f351782310b0eadc077db59abca0f0cd26776e2e7acb9f3bce40b1fa5221fd1561226c6263cc5f2244f474cf03cceff28abc65c9cbae594f725c80e12d96c9b86c3400e529bfe184056e257c07940bb664636f689e8d2027c834681f8f878b73445261034e946bb2d901b4b8782a441284214b9b9c85549ab3d2b972df0deef66ac2c98e82934ca974fdcd97f3309de967d3c9c43fa711a8d673af5d75465844bf8969c8d1948d903748ac7b8b1720fa64e50c2a4435552c16704d214347f29fa77f77da6d75d7c752b742ad4855bae330426b823e742da31f816cc83bc16d69a9134be0cfb4a1d17ec34f1b5b32d5c20440b8536b1e88f0f22a4440d3256eb0babe89f0ea54edaa398513136612f5a334b49d766ebe3eb9f6bdc163bd2c19aa7e8cee1667851ae0c1651f01c4cf7cf2cfcf8475bff3e99cab25b05631472d2a4476d76ee8823de52a1a431884c2ca930c5e72bff3803af79641cf964cc001671017f0b680f93b7dde085b24bbc67b2a562a216f903ac878c5477641328172a353f1e493cf2a447f5f2cf1aec83bf0c74df566a41aa7ed65ea84ea99e3849ef31887c0f880a0feb92f356f58fbd023a82f5311fc87a5883a662e9ebbbefc90bf13aa533c2438a4113804bf2a44980a75ecd1309ea12fa2ed87a8744fbfc9b863d589037a9ace3b590165ea1c0c5ac72bf600b7c88c1e435f41932c1132aae1bfa0bb68e46b96ccb12c3415e4d82af717d82a44b71b214cb885500844365e95cd9942c7276e7fd8a2750ec6dded3dcdc2f351782310b0eadc077db59abca0f0cd26776e2e7acb9f3bce40b1fa5221fd1561226c6263cc5f2a44f474cf03cceff28abc65c9cbae594f725c80e12d96c9b86c3400e529bfe184056e257c07940bb664636f689e8d2027c834681f8f878b73445261034e946bb2d901b4b878").to_vec();
        let height = 39981000;
        let trusted_height = 39980600;
        let trusted_current_validator_hash =
            hex!("674c4f3d0b24204759cd9b4d9a641bdeed6adff81bafe9965451045916b6b4de");
        let trusted_previous_validator_hash =
            hex!("efa11eef8adc20d6f179dff684c16891761d632462147830cb45579589632786");
        let new_current_validator_hash =
            hex!("8a4bca6491ec89e201ea0e2776f0ae42f7e5c8d67a305a7aa6284a0e0150f736");
        let new_previous_validator_hash = trusted_previous_validator_hash;
        do_test_success_update_state(
            header,
            height,
            trusted_height,
            trusted_current_validator_hash,
            trusted_previous_validator_hash,
            new_current_validator_hash,
            new_previous_validator_hash,
            97,
        )
    }

    #[test]
    fn test_success_update_state_non_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212fb460a9d060a9a06f90317a0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc41a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479461dd481a114a2e761c554b641742c973867899d3a023de09bdc6958b6144faa67c37966f2c1a8fb0697fb99b9e6a2340bb5be1dd05a0c834461f3fb915a33c55976be1bea82c54f7ff96ee284554346daa86d89d9806a0c61679f1e18d68a25b8598d05ae895768c0d6017198393f4c07d66b99221d6a4b90100812bae02ce1014d8885402d4ac1c150f9309418024012028ca0e4b3002c21800c01132417004ce41008139a008123203940e301980880004a00204d28d2420c2a42044820fe40060279d9f3cb14022f621d0126107668247210414058f206360b0fce6238a17002445cb199001c04d490a208041e24044aa2a00e710a4085101c51ae300021aa0718288a410e4408ad84c246c0528238048b510c044082940230b9a20008e22cda1260040042a8a0310040042023e88018583a235b068531469e30f045e04ac49c6809404a033105080200160809122403c6913704ea705f0aa2398a101b0c4d12253200ac32a0d099de93ae02da97223c811042a600c3914d0028401eab9cb8408583b00837a7f0d8465168255b90118d88301020a846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5831df7ffb86097df3baf86afba3c26f7f97e49223d62fd9c09d728fe214d2d06ef9f7c3416fdc310be297444b7f4b0ff2835a02858e407d574343436f249ebf617c094c80bbc5d19341fb4ea8c7d9024480f16c4856edb087c3b7a06b10c38920a43c8753fccf84c8401eab9c9a022c32b836e14bb6b733e91900715e7268b23efbe462314fbc500d36b425ba1048401eab9caa0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc4180d25d99399c6b8c0339bcfd6b516fb1f3d2413efd792cf3c87a7c34ae80ca147934267791f4635c5d3840c11b240696e9c889ba0ec411388251026105fa7e5eb201a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d99a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479470f657164e5b75689b64b7fd1fa275f334f28e18a0dd5169230dd630e4891f1356f1b96707176e5922adf7d1607d6235eaddd50cb7a001c548e269165c55330607dcaa0a13c7508ff56922757219a9050366b5833115a0224fc94974291205e108fdf540928481aa6ff640ad1ed67db7ea087dbd557bc9b901002a708b2a016850920a010e649218000223074a82c918008039019b851244021ca14931207014d88000404308001e20048a00581b10075420834024022928a2802c5042018540040041489808e0a2583c25182376014e0a4124c74210388301b1466ca5219e121828408108888b03c90308086440a84c04b93200c09c031425074709ca85a248c44e908b160088404898602e840438420868015080410009c460c69000006b66aa80806844440e42900370b2022098820a18100341e0c41286080881944a04480a871c2044418210d22020742940b808ca140d12548a0312a0001030ab0d016c2d2801318ad0080009680c2804f40468280899616f010a010140028401eab9cc8408583b008367bf768465168258b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831df7ffb860abf70f41702762f51619c42bdf6b9c3ba383175632b6db3cc238bc17364bf21562a51f228f68534e7b4aaaff35f8c5ce08fd5e8dfeaa328a76b0e6ebb85b5e99099b660ed69b759f014fafa7eecb3098292d75f82d0c471ef6f9511b4ef3f8d4f84c8401eab9caa0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc418401eab9cba004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d99800b315cd2d4e3162f9ccfb0a1c3bfbf57368525086dd5c0b18bad6833e2bfca3e1fbad1657e623968d777fec26778fd846e6664bbf5eac859dd09eae74d96bee200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0dc9fb461ecd0a1bf6349e94d61f78c783a511d0e773154f6593f2530dc8c5cc3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0b4486492538ac1aba093c1b5f303d47fdfc5be01cd5c67380e5e9760779139d3a037c90501705e0938b684c912c4bc8a2ebbbc46f477abf481e600262c733451d1a09219073211ceb3d89b20b19264464a28229a069c832e751f5452e7fb8b5efb60b9010052a0a28f26cff3f5004e00e4a39a044e8b084a42b48914c87a398316d3482614a6d2125560fbc0015063baf2041e401abd4bd410581be876371c29bb043e0a48864f669223440e39897b28298560542d7218016b437cc3aa28b6519482202e20c96cb4a98edb1d8f6d078b90c32c2b65ae80c41d0ee0c4ae9051de93c508e65082fcba04803651c7d3bc3482590a081c2c3c45c1ab33105930ac83405d02c530aa11d10553c30a14129042e4638214b96609149c6ace47e294644462e18acab0990b165ab81418225420106d0e34d160747963e4b182515451185e87a74be270b331ca0531290e2889276f12b400090a7900008d932867ce1b6fad1118bb520b028401eab9cd84084fe2c683b2b318846516825bb90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831df7ffb86099ff0d5d682bbb7d7a82a3e81c09b9fb4c3b3c2cfcc0f1b1d68ae90a678bbba5430aa814fb2102d6893c39de2e86c96f19d8d1e8cd93a5f86dd87c7639adf3f661e3ae238daa85243e03e8dee02e45d64556263c7b9d38a9fd250fc47791dc56f84c8401eab9cba004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d998401eab9cca0dc9fb461ecd0a1bf6349e94d61f78c783a511d0e773154f6593f2530dc8c5cc38040c23bea0a66f1eb621da3fd7184780591887e9a85a0b075a1df3e0cd6e14d522f9b3245bac947cfcc959770a65f63115fc2891b2043f675ca4e9e4aa6f2baf501a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510caf3aa0f1a951df90e92f90211a0879fbf1597c6a4a5c19795c1962370cc6de1ff693534c7bee22df95842990dcda0b22fc1e58162520af9a6bf4326027e307cec4342c9c3a6a9d6a32564363b0a2ca0f1654bf9e5e926a80711aff2934e073cf4b103765f9df3b069f24aef4d16cdf1a087c5469547200128d2c98237b629189f162e786bde24b500029235ec2ca89281a0e498ce1143f8c074010db7643780a87780f7578a41ec4a0f3bb2251369d68d46a0d3c655057035d5002eedc89b56f66bcf2d1b6fa8be67bc41d3c89be1f7722c4aa0284d823ebb6f34818f14ecc532b770540712f3aa1ca4df74e334bc253e6b32aca0f28ab40b0509b25fe9f3dd65f626f42729f52ccb9685b61b867469a321f21716a00f76ce464832957ad288c150ba1cadb0e590f316076a52a3344a37e70123c51ca0f02904295ad311f10ba192a1049f4816b40f7c81c651c88b110136d02e638f7ea021b037ac53fc4ea00c1da756df5fcd5f73fedb991cb716bfb9f946e07979833ba03144039e8987b82900e059f5780412506b75769f3b68609775a46112091297dda02641eb6e6277e93c4288f92338d04e51b4ef75a709852f73419d9da61c618cd0a01b65d747629e22c321c27bf3a3be57e9ee06e9f51193e8fbebfac66ad0e3abcba01cf92f3196475026a7c231bbf0f12cfc1f08b47fbcedc2a7c57b64e3b3832dc7a018767613ec3bea5597898b1dd2601c931ffcf0115547e23f84c06f320719db6980f90211a07f9d3901b46ee6b732d2aaaf84d40b47ebc831ed47adb8a2c1c43613de4605dba027cb7f21a746a9c6e76b3d4d0cc1da32111ca20b0d3f1cb64afd1d0462e8e211a0052f5245ea659debd6f38fc4789cbeb0fd2235aff77537e808e0e767196e8b7da0af67e75eb2f83ef984dad98b2e2d05a1b9e0d18175e7882e9ceb847c994f89a9a01af6bc0e3ec6cc384dd68218ed53f2799024d57d2c3a53523dfa227128699ceda040971b58d91a4e17e12065b5ee59134aa12173a581716893358ddb80ccd76486a0c68ac43d0dbaa844b812b91c527f70595d1c9fb33e49e373993078a9b6506f4fa0542841b0417994c8e689d15cf3d895a09d1e485ab9b3bf0b782b112792f459dfa09c410eeb054c0cd4bdcebab79f3dcd445ef33994e03b4f8336b1a3842c879261a0317498b85f2e60d0144557a9daa665b04858f6d67afa4692f6e40b518becc5e3a03e15531394d36f2cebabf69de2823a5a17994e85f6d4bc663947157c007edee2a091c0de5ac4131c6e9a625000d994dffb70f87eaa0dddb27544e731e2e04a066fa023ce1490b59b94bd8840af9c1a12f2f98f9537ddddee037209dd7881a114052ea0c7e8afeea81b08c7b07ab41e191b8c054baad1231db7585084ac90907211fc2ba068e094995972c8da18e345180551c04af0696b5b756d3f414dea3b41a15b575da0e22741ba7909396a84d3dbef5aeba6e6614638253a7319ec2fa6409cbde44b5180f90211a0e6d6c23fa1734c2f5d243a3cfb0f39cd02cfbfdb4bc3c8f431aed32fcd2854dda06bcf17926dad58b8c5118d5a6174fd085d03d92a9d4a5ed56efdd36f45975ea4a0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa091e6a46980bb716301891e6d65c420b2c25481f5f1fc0ec3e921fa1ec0b33e65a07ea284e90799149edd33ace9e67e83806405f98028558b45a5dcf6e411ac1d7ba070c2688533f8337332f5c7c11b1bd46704b7f2937d4683e509ca40cfb97502eda04b03a777f36dc9be61cca125223359ebb167562b64715f8aada6ee9f0219df0da093993ee43f49f3e33f6cb6541c6393dca4ac240893f1c0a250490f784d138814a085ae2d7b32dc0f0da002ea5033910b035e01f5ae12ff3105010e13a5a33c0ad4a00c39c1e39b90b4afab7648dd547f77b8f9d4c6d9e0c63e34ebf4c149c948edafa0e56b7c7c4656dd0b9f0919e09d6da771d38c453af4c0f0d6544f390fd2a543f7a081cca9739d3140249d6ae461371ff7b465883352d81bc757ca982f52d524c1dba0d3dbf7dcc484d241e77ee2be684b262f614f871a8c9d6598430a2134973782e0a09917ddd6820b6c66429eba999f5030141508a439dea8393b098035dbd283c287a0690b4d39eff7648da540434688e23bed68fe43f3711a9bc7dac7c15626fe1b7ba0c8af8672c865cd5af89c4a6b9e55b87f1dcf1ee0f76560a7d1f3c04daab60e4e80f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let height = 32160203;
        let trusted_height = 32160202;
        let trusted_current_validator_hash =
            hex!("abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac");
        let trusted_previous_validator_hash =
            hex!("dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71");
        let new_current_validator_hash = trusted_current_validator_hash;
        let new_previous_validator_hash = trusted_previous_validator_hash;
        do_test_success_update_state(
            header,
            height,
            trusted_height,
            trusted_current_validator_hash,
            trusted_previous_validator_hash,
            new_current_validator_hash,
            new_previous_validator_hash,
            56,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn do_test_success_update_state(
        header: Vec<u8>,
        height: u64,
        trusted_height: u64,
        trusted_current_validator_hash: Hash,
        trusted_previous_validator_hash: Hash,
        new_current_validator_hash: Hash,
        new_previous_validator_hash: Hash,
        chain_id: u64,
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
            chain_id: ChainId::new(chain_id),
            ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
            latest_height: Height::new(0, height),
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
                assert_eq!(
                    new_consensus_state.state_root,
                    hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                );
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

    #[test]
    fn test_error_update_state() {
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212fd460a9e060a9b06f90318a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda85a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba00000000000000000000000000000000000000000000000000000000000000000a09327a61481b2408f2a2d3cd4c1956259215eedd9f5f4cfe53ef0df89e80f335da0b35856be0503b120103115c6bf48ffd750e2e83880676f70dc34d9a50e64c247b9010086260674d1c0d73c1d5439558051687683845288bc1a18743c2f814631882c40ee4cb9a2e88cc19c00d0ffba0a9e52229b8ec1199402712450c0e129dd2e34e1e76229f4ff416ca91999c02be1244ebe72319828856ee26620067491c7350a60c8ec82234aeeada54d47cbb2d56cad888acace4fa8ad4d781a086a10834a41c1ced08b15a31d0fd6d49a74ac4c9859de90678ec168b1447b2ad14aca95820d302bdf881553828a51931897e70e823cdb756ad6a59e860337202804322910cae3e53a565e4a00acd75e272289417757352275514595e7b09de390550f72b0fca83118a79791f57909630507827a144d4015e48d3be9ba43ca3b6684307a210ded028401eab9f784084fe2c68401193c0f84651682deb90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb860ae89c1a42abb17a167fd49be92d22898e1a449743966cc36a8813508a5e5f8c180e0a2713d5cc8d748acd0fdb95c3a9d0134fec56824b3b1901378823ffd3e98d36bd1574329805cdd96499704ce21dfee1c3b35e744a4dd5f2e8c811a939143f84c8401eab9f5a04faca5268b7a0425eccecac9a27a75e9e4e6abeaf018eed562ef01a8ff8f6cd78401eab9f6a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda85804ef67727f6a4a908a26a1229538a5b7f90bec3e2e6b8fc5420045b8c5520343932847f59933c3a400d088d5fe9f5fde2ae5809ac8b3a11de33e7818c8fec422b00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f28a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947ae2f5b9e386cd1b50a4550696d957cb4900f03aa06afbbdd36cb61f3d2a651bc6218ef4b7fb7ad2367195105a67e952189dbc3188a03709615ddca48112289d87be4f8083e7067d4d0898f983132558e12a897c1d87a08227455c29c40f1bbbe4792e2b9814d98cb622d862f5aeca8373dfae7969e8deb90100527986d63768151ac9100068b058b15181120286f3710c10315231ea512011068a40b85371d9920143217125061e0022a922251aa54b564851d018b5322e06e84e0284800b610c5011b4488daa630abc30d8092409742d4185661a5480143d20483ab8b35a2b61e64c53181051490f3b18818f5d814c05a453e7ac982a08455010e2e4213709480d8ac067480a4c09b8066c8cc5310e01084b99ce6078f20c6fb3d100f256e88197218058454b8ec711314200612a0a4325b022a66824eb28cee540cd62006443c712205a0d423fd94d23d1af94d00215dd6512d4d60064e57408d5a043c0e8c3ca231402ee4820e524710004104738446ebd5b151e4c614844028401eab9f884085832a783cfa37b84651682e1b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860a1f5946901ac7f9e875f2fdcb906700be782d4720fda4bf4c5e9680b62608c09c051723f6eb08edca330815bf3836987093575166c87a59e64cc7798737d2c4d3eee7b080d888a5454e689a3df1a6e1d2b655dec52ae3f8c444b90a93ea478b6f84c8401eab9f6a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda858401eab9f7a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f28804f1bcd3484aea92f5ab7772ec713cb6f94b092c251b5ae134bd178111aaf5ce95b23b86e4965e9578cfd6240ec8b7a6effa75aecaa6326cfa42aceec2b69a59200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9e060a9b06f90318a05c1a4ac59fa493c7add0898f753bd3b6eca7717d0424cc3660d9908233989079a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a0f82ea8b35f53773563a8ecb3287113bbbd5efaedcd09834667e32212ff288fbea0689b79ba82934bb61ee8f64af6f980d9bf164419dc9329f9d62a33b621e1a5eea06f8a552cbb9e52bff118baa395c75251a3b582c0b6dcc93bfc4fa0a15cca1dd5b90100cfa64722a69e3dbe2e9978dcb71e5cff8f31e4f436e949285fa0ab4f3b89ad5fa7b1d411f036b680cd1a337a4512e71b9f1f1eff1192aa4066cd5a1e743c2a82bc41ead1af65dc218d7ec42ca585c7bf699f91a4f354da97efacb534e051bc91dc3ddb35cf07d9cc544f9daf23632d192c3fdf498a81ed387a70b615fe8728d7d5ead0ae3a2100759197b4115f766988213e2607ff25195b2d5526c68b684cf5bf910071e2afab080fbc1dce2f9e9c9a45e3035d3ddbfc2962543e22eaeb3c60d0acfe2667a46d6e10d398b91c33d4e06671fb9a959f8f3d4511d5febdecbef813f2c752f3f3ddb8893758fa30ab83f972b24c1843b34ec81e4fcf5ef8ad6c4a028401eab9f98408583b00840129f24984651682e4b90118d883010209846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5831defffb860b0f58980edb50dd10c56c83443f5ebd140d430a422bfa1168da234e15187977283647b7ec30a3443a2d5bc5c705ea19d193782aca1a29a5adf2e8378e2c86498185700253f885dbf3c58d05a785f9bb3dcc914fbbbcd4addae9aaf8a3eea0575f84c8401eab9f7a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f288401eab9f8a05c1a4ac59fa493c7add0898f753bd3b6eca7717d0424cc3660d9908233989079809d9d51ff8ea924fcbb62f90bd0a6185457a3a5c6e7d074acb2d35373e02ab466039d3d23c795be05eca2773251b0bb4ac7dc25e247d3f295ffb6421e6b65fd5b01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510f6f3aa0f1a951df90e92f90211a05760c478b528201548b880f9df75f669b35285dfe4bce3a2245b6fdace23806ea06702ed5328fc88ae32788582fdce6087c3772e9f2872be07dddfd72bce23e6e6a076fecf1768f2efca0493b32434dc758cb1804a9eba8479ecc244490d02016850a05fc46706b33918b46e21e0552215669313eb6fee038e8662a364d450f20b765ea02162336e1f97ea3aaaf26e5482e752e3bc335f146b08a4ec067bb2f6b66ad4eba0f9c52bc52d2bff446b57580612ff3d5e5ce63fe38ae9a6c286068fe6d8dd69e1a0f2ffb55c6c86989060e530e9300716eb81b402ee6e54d6845e40f256cc5a30a8a040307a80bb9b2672c1ddf9e009377bf6f792ccb6471975a7efbae167310f32dda0ed0a7cf42511cdf4c79e1cf995074202e10b148e9d8cc9ff459ea63bd456c292a0d8642102cd0c903c286313b4da9fc2d576f819d24c5dc9decf7a72d6c5f3a6f5a0a72af8ac881122fe9e28643d845ec0bdb82e7c6844c4e90d1375b3b6d00b2e83a027e16ad7e44adc72b9f25459e50d59ebdfc2df5210a317e9af7e6953001b06d4a0e2c69d81c457b2499b10a65b4764ea149ce06c38e20a1b81034c86c1072ed008a000f2f7a39a9572c5eaf08e46f20a46f2b3b9f0dba44940cbb3b717e8cb72cd0ea053da4d2d3e34749b27aa7867bc4eaa05c33e5ebb914eb7a2eda4337b302fa43aa094da8ed2b23a83012b966d1361235fc24cb33a0886be41d9ee19862cb313094580f90211a0a2128874d2823da6bd7cdf67438effc0e407274501327d2405e25687585eb70ba05b0986965e23b96ad60c8af08434733c40efe29db0c993d7ba9bc4ffa1483ba8a0f43d30c11169496786df08702b0080269f67dec4afc589a629f481b16d19832ba04a12b6f2493e006b66605e1d00af7f6eb3f6c733dd84cf40ddf5f89267e8e7aba064e170ac6680f6cdf1e42faba258367fcf0393b6b2ccdc896d90acbd23ab5465a070771a010394851774d88d286b57bdf9faf9d9356a2240128eb9de145ec2edfba02dc8752dafe069b464c36b8509826d726c1f131f205a49fe8788659122203620a0f63f4e9a984f664b13b67dfe922fc3a560efce6720b9172614e11965dfa3b711a05afa9694c979c6904d88cf2f248a755f41b78a44ecfd7861bbf11ab617528723a0b5d0e96e1a30c464bcbadf2fb1e6587f30c26e611912bc71298309869803e01ba0bb30f6dd3be410db17d680911856ad5068698256462beda07b6fa0ecb2c795d6a016d61ebc2df2ae26c81a9e42e21e690835a3855cd5fb8b080914b29e61b0cba9a07f3f00a25937d9fa7f5fab4e72c39e7c61e2744c3a7f98489ab4d1b2e7caedf3a0cb308105ad0e53f8295d98d64926f0e932459a9690b5a54bcf5557985cf4e401a0e5fd124381dc44dcd9fc74bdc6d9e73eed51c739aad2270730c146a80ae4f1f2a02bdd929c52fb5bbcb95162cce765015a272ef934c1c0c7ed38c8ca2c0bef5ad280f90211a0e6d6c23fa1734c2f5d243a3cfb0f39cd02cfbfdb4bc3c8f431aed32fcd2854dda03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa087492846af03fde43add538ba9a0cd3a58dda4f92af41fa5ec85c724b3569952a0251aab0f729960016c67c4450afcea003fe27516ae12a4aacbba88c2218d609aa00773c02f14993b861c986adb86c48e2b964b04fc93b7c14e0adf236ba48fc3c3a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa098e233266cb2949de7efbc5249a002cd0e347ee19307a53498a6d46ae5dd5e5ea0668cead9c0b63d7ebcb34a1a5864a894baac5fc4a85fae89ff6301645b1a2c5aa0001d500e083c7b36f84d6d19af62df79986281f6c826e47f44d7b97c3d106af4a0607867cd831b1cac0eb801706ed0a6c762746c07b8ee12870445c526da6058a3a0c82d3b93fbfab9bb7d75a7eae35fb9ab46558857867d24d65de62e93befd63bda0a39ffe983c540e96c66156dc256c27ab556267c1169629ebecf09c11dca8ad7fa09917ddd6820b6c66429eba999f5030141508a439dea8393b098035dbd283c287a04d959bbbe8ea6b950a3c865aca329123dac37debff5ea2531c8a25af9e09b1eea03d184ecdda0c942db6d34a492675d82093b1bdea5eb088d69e6502fff16bc71980f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let any: Any = header.try_into().unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
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
        mock_consensus_state.insert(Height::new(0, 32160246), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 32160247),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        // fail: check_header_and_update_state
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedHeaderRelation: 32160247 32160248"),
            "{}",
            err
        );
        // assert testdata validity
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
        assert!(
            format!("{:?}", err).contains("ClientFrozen: xx-parlia-1"),
            "{}",
            err
        );

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: mock_consensus_state,
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("client_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 32160247),
                ..Default::default()
            }),
            consensus_state: BTreeMap::new(),
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert!(
            format!("{:?}", err)
                .contains("consensus_state not found: client_id=xx-parlia-1 height=0-32160246"),
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
        let expected = format!("{:?}", err).contains("UnexpectedStateValue");
        assert!(expected, "{}", err);

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
        let expected = format!("{:?}", err).contains("UnexpectedProofHeight");
        assert!(expected, "{}", err);

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
            current_validators_hash: misbehavior
                .header_1
                .current_epoch_validators_hash()
                .unwrap(),
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

        // assert testdata validity
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
        assert!(
            format!("{:?}", err).contains("UnexpectedSameBlockHash : 0-32160267"),
            "{}",
            err
        );

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
        assert!(
            format!("{:?}", err).contains("UnexpectedHeaderRelation: 32160267 32160268"),
            "{}",
            err
        );

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
        assert!(
            format!("{:?}", err).contains("ClientFrozen: xx-parlia-1"),
            "{}",
            err
        );

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("consensus_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: BTreeMap::new(),
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert!(
            format!("{:?}", err).contains("client_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );
    }
}
