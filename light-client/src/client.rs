use alloc::string::{String, ToString};
use alloc::vec::Vec;

use light_client::commitments::TrustingPeriodContext;
use light_client::{
    commitments::{
        gen_state_id_from_any, CommitmentContext, CommitmentPrefix, StateCommitment, StateID,
        UpdateClientCommitment,
    },
    types::{Any, ClientId, Height},
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient,
    StateVerificationResult, UpdateClientResult,
};
use patricia_merkle_trie::keccak::keccak_256;

use crate::client_state::ClientState;
use crate::commitment::{
    calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, verify_proof,
};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::constant::BLOCKS_PER_EPOCH;
use crate::header::validator_set::ValidatorSet;
use crate::header::Header;
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

        let new_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        Ok(CreateClientResult {
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: None,
                new_state_id,
                new_state: Some(any_client_state),
                prev_height: None,
                new_height: height,
                timestamp,
                context: CommitmentContext::Empty,
            }
            .into(),
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_header: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        //Ensure header can be verified.
        let header = Header::try_from(any_header)?;
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

        // Ensure valid validator set
        self.verify_validator_set(
            ctx,
            &client_id,
            header.height(),
            header.target_validators(),
            header.parent_validators(),
        )?;

        // Create new state and ensure header is valid
        let latest_trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;
        let (new_client_state, new_consensus_state) = client_state.check_header_and_update_state(
            ctx.host_timestamp(),
            &latest_trusted_consensus_state,
            header,
        )?;

        let trusted_state_timestamp = latest_trusted_consensus_state.timestamp;
        let trusting_period = client_state.trusting_period;
        let max_clock_drift = client_state.max_clock_drift;
        let prev_state_id = gen_state_id(client_state, latest_trusted_consensus_state)?;
        let new_state_id = gen_state_id(new_client_state.clone(), new_consensus_state.clone())?;

        Ok(UpdateClientResult {
            new_any_client_state: new_client_state.into(),
            new_any_consensus_state: new_consensus_state.into(),
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: Some(prev_state_id),
                new_state_id,
                new_state: None,
                prev_height: Some(trusted_height),
                new_height: height,
                timestamp,
                context: CommitmentContext::TrustingPeriod(TrustingPeriodContext::new(
                    trusting_period,
                    max_clock_drift,
                    timestamp,
                    trusted_state_timestamp,
                )),
            }
            .into(),
            prove: true,
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
    ) -> Result<StateVerificationResult, LightClientError> {
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

        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(
                prefix,
                path,
                Some(value),
                proof_height,
                state_id,
            )
            .into(),
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
    ) -> Result<StateVerificationResult, LightClientError> {
        let state_id =
            self.verify_commitment(ctx, client_id, &prefix, &path, None, &proof_height, proof)?;
        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(prefix, path, None, proof_height, state_id)
                .into(),
        })
    }
}

impl ParliaLightClient {
    //TODO impl LightClient
    pub fn submit_misbehaviour(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_misbehaviour: Any,
    ) -> Result<ClientState, LightClientError> {
        let misbehaviour = Misbehaviour::try_from(any_misbehaviour)?;
        let any_client_state = ctx.client_state(&client_id)?;
        let any_consensus_state1 =
            ctx.consensus_state(&client_id, &misbehaviour.header_1.trusted_height())?;
        let any_consensus_state2 =
            ctx.consensus_state(&client_id, &misbehaviour.header_2.trusted_height())?;

        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }

        self.verify_validator_set(
            ctx,
            &client_id,
            misbehaviour.header_1.height(),
            misbehaviour.header_1.target_validators(),
            misbehaviour.header_1.parent_validators(),
        )?;
        self.verify_validator_set(
            ctx,
            &client_id,
            misbehaviour.header_2.height(),
            misbehaviour.header_2.target_validators(),
            misbehaviour.header_2.parent_validators(),
        )?;

        let trusted_consensus_state1 = ConsensusState::try_from(any_consensus_state1)?;
        let trusted_consensus_state2 = ConsensusState::try_from(any_consensus_state2)?;

        let new_client_state = client_state.check_misbehaviour_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state1,
            &trusted_consensus_state2,
            misbehaviour,
        )?;
        Ok(new_client_state)
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
        if client_state.latest_height != proof_height {
            return Err(
                Error::UnexpectedLatestHeight(proof_height, client_state.latest_height).into(),
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

    fn verify_validator_set(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
        target: Height,
        target_validators: &ValidatorSet,
        parent_validators: &ValidatorSet,
    ) -> Result<(), LightClientError> {
        let epoch_count = target.revision_height() / BLOCKS_PER_EPOCH;
        let previous_epoch = Height::new(
            target.revision_number(),
            u64::max(epoch_count - 1, 0) * BLOCKS_PER_EPOCH,
        );
        let current_epoch = Height::new(target.revision_number(), epoch_count * BLOCKS_PER_EPOCH);
        let cs: ConsensusState = ctx
            .consensus_state(client_id, &previous_epoch)?
            .try_into()?;

        let previous_validator_size = cs.validators_size;
        let checkpoint = current_epoch.revision_height() + previous_validator_size / 2 + 1;

        // Ensure parent validators are valid
        if checkpoint == target.revision_height() {
            // The parent is checkpoint - 1 when the target is checkpoint
            if cs.validators_hash != parent_validators.hash {
                return Err(Error::UnexpectedParentValidatorsHash(
                    target,
                    previous_validator_size,
                    parent_validators.hash,
                    cs.validators_hash,
                )
                .into());
            }
        } else if target_validators.hash != parent_validators.hash {
            return Err(Error::UnexpectedParentValidatorsHash(
                target,
                previous_validator_size,
                parent_validators.hash,
                target_validators.hash,
            )
            .into());
        }

        // Ensure target validators are valid
        let cs = if checkpoint <= target.revision_height() {
            ConsensusState::try_from(ctx.consensus_state(client_id, &current_epoch)?)?
        } else {
            cs
        };
        if cs.validators_hash != target_validators.hash {
            return Err(Error::UnexpectedTargetValidatorsHash(
                target,
                previous_validator_size,
                target_validators.hash,
                cs.validators_hash,
            )
            .into());
        }
        Ok(())
    }
}

fn gen_state_id(
    client_state: ClientState,
    consensus_state: ConsensusState,
) -> Result<StateID, LightClientError> {
    let client_state = Any::from(client_state.canonicalize());
    let consensus_state = Any::from(consensus_state.canonicalize());
    gen_state_id_from_any(&client_state, &consensus_state).map_err(LightClientError::commitment)
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use light_client::types::{Any, ClientId, Height, Time};

    use light_client::commitments::{Commitment, CommitmentContext, TrustingPeriodContext};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};

    use patricia_merkle_trie::keccak::keccak_256;
    use time::macros::datetime;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    use crate::header::constant::BLOCKS_PER_EPOCH;

    use crate::header::testdata::mainnet;
    use crate::header::Header;
    use crate::misc::{keccak_256_vec, new_height, ChainId, Hash};

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: ChainId::new(9999),
                ibc_store_address: [0; 20],
                ibc_commitments_slot: hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
                trusting_period: core::time::Duration::new(86400 * 365, 0),
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
                validators_hash: [0_u8; 32],
                validators_size: 0,
            }
        }
    }

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            Time::from_unix_timestamp_nanos(
                datetime!(2023-09-10 9:00 UTC).unix_timestamp_nanos() as u128
            )
            .unwrap()
        }
    }

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

    impl HostClientReader for MockClientReader {}

    impl ClientReader for MockClientReader {
        fn client_state(&self, _client_id: &ClientId) -> Result<Any, light_client::Error> {
            Ok(Any::from(self.client_state.clone().unwrap()))
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
            Ok(Any::from(state))
        }
    }

    #[test]
    fn test_success_create_client() {
        let client_state = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e745374617465124a088f4e1214aa43d337145e8930d01cb4e60abf6595c692921e1a200000000000000000000000000000000000000000000000000000000000000000220310c8012a020864320410c0843d").to_vec();
        let consensus_state = hex!("0a2a2f6962632e6c69676874636c69656e74732e7061726c69612e76312e436f6e73656e737573537461746512460a20c3608871098f21b59607ef3fb9412a091de9246ad1281a92f5b07dc2f465b7a01a2095ec85e33c9b37a199994464ea84512a8ebbb62dea3817dbe2f8eacd7c702ff12015").to_vec();
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
        assert_eq!(result.height.revision_height(), 200);
        match result.commitment {
            Commitment::UpdateClient(data) => {
                assert_eq!(data.new_height.revision_height(), 200);
                let cs = ConsensusState::try_from(any_consensus_state).unwrap();
                assert_eq!(
                    data.timestamp.as_unix_timestamp_secs(),
                    cs.timestamp.as_unix_timestamp_secs()
                );
                assert_eq!(data.new_state.unwrap(), any_client_state);
                assert!(!data.new_state_id.to_vec().is_empty());
                assert!(data.prev_height.is_none());
                assert!(data.prev_state_id.is_none());
            }
            _ => unreachable!("invalid commitment"),
        }
    }

    #[test]
    fn test_success_update_client_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212f14b0ab2110aaf11f908aca0f6ac769a0025c9f14f3b68a2c62512a923edda1f47a388d50f978d0d4a4570dea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942d4c407bbe49438ed859fe965b140dcf1aab71a9a07e850baa1d540ac80cd46bd19d45d44a46b288bf223fc59168a98c941499ed8fa0dcfb0664efb647d1eabb456349d81c9d449120152f3ad534ef605a6e63be3751a0710b44dd29d5b630d62052c5529dd0a23693f830c249f0687668ebbe72bc56c0b901000db012f4a444755a0a5cb26c941000cad620f100a3885850af0bfd0b37f3311487241a2575af0205c268386c41be321780fa32d0104e76f0c70210da252436d8ce4d4529a95830a0075e588df323f43d69911de719c60412c48cdd6ce862e400df6c09668a469c312a47e390811c19290dc958f3190bf4ae4685fc55104805a2206ab144913438283a9c740555c0aabc16ae0489e9201648139820c0dcc054292b22289052879b717e4c2f3c62a76604ecaf80b36f9eb683db04602360586c8fab3ede063055d85332931023b5c2b024b751a2421c8804f60379f5bb9762e5613ad28b0588f748010bb7a4660943a30119748b200594c45c353d6cc2f820005e028401e0ab908408583b0083b4ce368464f8408bb906add88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2150bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c816295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab03f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a61dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25685b1ded8013785d6623cc18d214320b6bb647598a60f82a7bcf74b4cb053b9bfe83d0ed02a84ebb10865dfdd8e26e7535c43a1cccd268e860f502216b379dfc9971d35870f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba772b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a517ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d78869485a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b741b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de7b4dd66d7c2c7e57f628210187192fb89d4b99dd4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cdcc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a419d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce739e9ae3261a475a27bb1028f140bc2a7c843318afd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c192183ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5bef0274e31810c9df02f98fafde0f841f4e66a1cd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f8b5830577ffb860ab6d818df2c2bd16619fa980d394da1ffbd28da874f0fc870ae32767f6ae404b75ff5e291c69275f4603ed9071a0fe1416ffdd01b440c682c5b34d0c78564a9ba712033fcdfbcb847995c9b16294ee198dd225f7f5f1ad96a03222ae5ef9b3c8f84c8401e0ab8ea07cfcbc85fd81638aacbf263d8482ffa2686d99f3bfe4579123f03c0b42f638068401e0ab8fa0f6ac769a0025c9f14f3b68a2c62512a923edda1f47a388d50f978d0d4a4570de8033b0debefa5bf4e7b9c865412beae551bb5a5c3f95464f0887bdd95c60a6a6b6539a36d150c6187b53712a19c7e3a673b8657a597f1d9f39fb8b21a7d6253c5b00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a07cfcbc85fd81638aacbf263d8482ffa2686d99f3bfe4579123f03c0b42f63806a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794295e26495cef6f69dfa69911d9d8e4f3bbadb89ba0354a24783ddc9355e2982eccada0c2986832c57acf83e9d4e9ecd5d988a344b3a007fca39575f2d97362214b9e5151fa218102eaa759369a15cb89a0d1fc5ab1c9a03d03b92d4902c2d7930fc5c4fede5634d65356175ad26dcca41c9a795009130cb901007cfafaedd478541aaf5c3256969a5a76f75bfe229e9c137f6e8bdfeed093c9b296499ef675ace88957eb7c9d5fba2e30e63fe459310937ce7096aaee462dfefeccc87e701d549829c9feffee8bb598fd29dd4aef366eab4e36fcfca5fc6e3ed85a5cee778fce3c3d6b5357de47d61c9bcfbd40ef19c9ffbc26268e71dd724b3d4d9aa0942eabc7cf3f89b647fa42e9b8bfbefdcb6f3c77eb2f5219d889c4792c0e028691f6ced37faf7e8ed7efdce714fcb52e5dfbaf6f395f943abbfddec8f3b8b75f626c3b4ccf3df562b929eaba64eae5f4641d9cd555fb55557efa6df5fdddbf87c5b3cbfb264f6fcec7e1b579207f7cc6b1ef3f434eedf3851d1b75ddd6028401e0ab8f8408583b008401543eb08464f84088b90118d883010209846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5830577ffb860894a04f0c835981bf5c08144180ffc024d07b3c21f01ccadb30f629f83b9239cc9d518d0a7e5e772e318d532dbbd641113613b93366b9b5855c398852f680d0b172ae56a8a3eee46018e2cbd0f9cc43ac33b659324438fa396ae20f81dff20cdf84c8401e0ab8da00ba1291c1d179a1bb21f9dc587a79655177780f1c5cc67d7b0e69588b9ce21108401e0ab8ea07cfcbc85fd81638aacbf263d8482ffa2686d99f3bfe4579123f03c0b42f638068073589c5e96971f030d75344cca1ed56a4825e0632d2ca6bb8531b08415ec23f949f7216aa6a8c6517bfdd502c2a3c67cbd099937f71fdcbee072c92826b8e66701a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a05108fd7820f22951df90e92f90211a00964e3155b81fe7c9327a9284f05f4296d6a04a4d6730ba1f634f2152277f6cda0957e41ffbf96a4e0f3f43060b8e4adbe4150e04ab2935b971fab4f227b167654a0528c1031fab6ff52277beb5aeae6ccc030a9d93c691ccd20c89ddb1a73734449a046d99bbaa3833bef5f9dbda789c9154d0f1e623b5d5e429645009d69f38ea0a9a0c2f8d760e6c456185e994aefbb2865f47e705fc60dd85038bf9cd05198b375cda09e9bc8ae5d61e19d8050fc16d792acbde61f7f08523c262272572316abd223a2a08d672502afb93970e159fe82f6eb85220fa1a0792c8c1b682ea25ea3563ca8dfa024bf8aa60ad87263ec488a48ddb000a742eea3b6e26686c1366ea8587a41be28a0b2fa2f805f410f8b1e6cb66b712e819823cff50ba917bcb182a33a49636e8bb0a09781513539ef27bf289c664bb9be7468cbf85725bd5861a039cabfba483c6ac0a0b25a1d7a76ae229e2d44041c46fbfef2ddba9868204e864377835a530b64fd88a062ca1a5ff0c05a14a06642caee0bca8fd9313dae192408e3ab1b244daa3efdd0a06d1061ddd8438e3110f7303e9bd0c6b9f74968b00d604ee33d4abe66a91812b3a016c17aa400ae30d87672284167c9b8e07dd7bb1e51008fb3d60b328a01150f89a0955750ed8af97233861684d3df1edb1231d4634255b0c2bec2a08134bd16b688a0cecb933aff647eb790f69f0339a2e9002d1c411a4f1453761665e96c43a80ccf80f90211a0c668792835d296132453b796d127fe4cfbcba68622b96e642452465254ce9676a0eab2edd59f6a24564f5382c5d152b2d6ed63f61e4be71722e1e2e395be0940a1a001fdea6466fb10d421a12e72959699a4292f47df4d2fcd020c95095cad36398ea06411c14c3957ef14d7f25e33a69202af63e6da360d1770e3b7fee487db46f57ca0662431334b01d1687f1c5e31219e8efd20adf7d03c19233dc1d8c0e33170ab04a0f19584ad036dc3597066d93a999009e40984458eaab4f900320c7475fc83fd0aa0b0b62cc119478d1736ea03d78a54a845b9f07802bc0b304023d9b8b8a242d6a5a0215e013cbcf3c7e164d7622a6bed8a8d31d5dc458ec303de2613fb9088fcb574a0d0c2e83e204fae24926c2b54af8f460cd608c2792d62bfa0817c062227f23aeaa0982481dc3324991e287a36ff98f62140ec350fb205ce73c40861d1b537ca567ba0973a0c050970303707cbf4518548753e6694ea7b39a102e43a2075d6a1dad584a07f337826faccc425946bc62304eed22557c8a2f0c0e9ce579d577f44b1ab5b24a088328aa6bfc4d16e10116bc0ee52b4bfe79be230ae08b0cdd425591c86019346a030262756bcdd2eaa6e004a332501939575fb51d1264c88a32b0df79c15a42ad7a057a30ecfff488bc881fdd972a678595ea60924773f4a9ff11e6a65d64f72e64da017f758d2044ddbea0f33de984985dfbb0d8664e454a53fe1ef2f85c09ff989cf80f90211a0c77ac60eb17a20b5c80b83036dbf6811cd0aef0a6bc1b2a2153a75642c147c33a093200ba226d6b0b33b7ce2446a96251575db6d801be8ffd61d61d4c9e18b1928a0b70ffe8303b0075b2fa611d67f064c7fec59bb9403b11ac0e8b821c7599ebedca03e4ff222417bec1f369a5bd1f451d72f56910c31dd052d16e31d38753a404c28a0d49c1ac57fc9c833e71844a858ba560ac599497d7b8d35fcf859513670dcba36a01fff647eca8a9627d525db8b18c6633f8e021e1123faf47cf629badceb529c55a0eb545ef6a47e949b786149d24e35cd4a60dc7165af9bdcf7933bab1c83f1a98da00514000c38197916cd26cb3949d68880cbcbce09f3e8646bc11ea53473639c0da083c06439a937b48ab457a654b2f24eed307d6db2d86de6bd481a0ae4fb055fa9a04bc0c2dd7f7fd9bdd0100db71520be8dd15520796f75023448c86efbb05110fba07f53ad5c27c83b8b868c1a8f2c2b54d720a32ec2206b15c2c44121fc1a495aa7a090d69477356d1c46d2f1b61847bf07a9098d3e45de19e5a88029177d551bdca2a0fa7c2949fb48cb97d04232ca0c14dbc5cd19f9a7e1e16e4f3f255430b6b04b42a01a6d05a474a53ba7cc9bb18eead8da7baf94e5782b51d9a2eeb2a98f68b76246a0c09ed689e6f3f3a6e1df9b9166091a1efcd9a47b0d72e5c12bf169738f92fdd0a004089d3d926ddd731f8c21457c5a8eff5cfa4b1bdb961908234701a4e7c8786280f90211a0dce33de62bf49fdbf1d19e0fdcdf7316b3e9e9ee28e936c944501325cde41245a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea08c29f96efc5cc63adaadad0e4b3744f3c0885dcdee2c02fd40583185f6e53b7fa042fed6400a66aef5f2e3c55636f49854f489881f089526a003ac78ecb42bafcaa0cbc367ca405a383f79dd4d3093ec402971c3247b1ccdae582f9a3367ce725d41a09b7bc1daf4e8e5e1cc66aae5eb99a35c4a0db889f9000d5458543da691d4da44a03031591e222c77f503c53473dd7196a6666c6bb04a1400829653fcfb49d119eda03930a8efca0e9cff8d775129523b348158b6be19c64e6201ed2e00812d752c2aa0f8ff11e818899b1c883c246af93b4c51071520f5426fe94ba74fd048626446afa0385401466420285419fdf931b147158e190d8dc09fae48acd09a77f81d51096da0dfac6948957e8c37e3ca9e4099ad01019ec7093bd76659b01f8457e83d6939aca03f75966fa80aa9b4cd0a24033937132d18f3dbc506fdd3c3d7a443a5c120becea03e063f9663a92a03f0420fb81c31f80948adf88992e49b9f7255efc4c65512d7a0de3920cd5b33f70046dbcc501aeb61c419d80d751aeee6179fc0a8dbc5fc8832a0420ed21a865ef6da26e12bd3cb40fd8bde2eaebea90c2ed94e1d32cebbeb80a1a00d2179d2e9ef7bce1325f27a3a0cd57e74addf198704e36c89c0065ace417b8f80f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a0bfe5ac7b3ede31763437dbbabf98627676721edea9c9f536c75cd8a705905e48a0ed9b9413f89286332c3dd5e7047bcdfc571e14a5345e74b727befc02e612ad49a096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0f1b54ec574ab3ea2c76c90f1241ab0d74f4c8da90749f81d9f118366105bcf0ca04f3ae8e50f70c066723b2208e8330af99fa42a0fd764c88f40585c1948648a50a0899d9f7f4b3acc15580275d4444d4de5604a9a31bf10abf52c0729d30d2f9c4aa023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0b749fecc509a19e4ba21e91be9cc2230945e28373c35addd3319a689e063735f80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a4435ebb5849518aff370ca25e19e1072cc1a9fabcaa7f3e2c0b4b16ad183c473bafe30a36e39fa4a143657e229cd23c77f8fbc8e4e4e241695dd3d248d1e51521eee6619142a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9132442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab0324435ebb5849518aff370ca25e19e1072cc1a9fabcaa7f3e2c0b4b16ad183c473bafe30a36e39fa4a143657e229cd23c77f8fbc8e4e4e241695dd3d248d1e51521eee66191432443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a324461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d2532447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b3244ef0274e31810c9df02f98fafde0f841f4e66a1cd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec();
        let height = 31501200;
        let trusted_height = 31501199;
        let c_epoch_height = 31501200;
        let target_validator_hash =
            hex!("b09a09acda1e471c6ec1f2e117e955dcb4d9f7eba59807b59aaf0a4cfe2d595a");
        let target_validator_size = 21;
        let new_validators_hash =
            hex!("0a5f91f29e09b6922f295bb0aab6ad63da3324255b88c83b1224d492aeb3fd32");
        let new_validators_size = 21;
        do_test_success_update_client(
            header,
            height,
            trusted_height,
            c_epoch_height,
            target_validator_hash,
            target_validator_size,
            new_validators_hash,
            new_validators_size,
        )
    }

    #[test]
    fn test_success_update_client_non_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212db400a9d060a9a06f90317a00a63bd8cf08c87d9997431a1ae783dcd41d1fb6cf1af6102fc28af56a12a5bd2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479435ebb5849518aff370ca25e19e1072cc1a9fabcaa00f9a100b180d4e4b983acc9887fd56f6df79828353138f6c5ea1f4fc5c1d65fca03f74c213aeb306d75a215fc7bd9b64db62b95992fd5ca5a0cb5b818a16c11e5ea03d6287956dd2a71fe0f19334b7eb2f5a10d4d3f25f8dbaf885dee3909c5d2e19b9010000ac2648b02c125864981f5c85da1002a609c0de4008c589cd08216383858030c26550d140629804c222102900365582a5495018111c2602381300220b243b808d60d68011e18560091b02a8b72420b82938b02207c6b800808d3c4a88921415c80e05239b124420245300a083c6ad090c108271000b56862829b618a88095651318a73c0321105b008024244840caa91437640539230448a10894d20a3853a04a0b01025774ab008f10c64f0e903491562510680a000f41026a0a20629902d34c281dea478a09c7325082025800d02aa18b72008040b116c110ca1ac062e4781c7c944204b4d1d0011334c6040125485aaeec85802876c8290042411aa5444a028401e0ad0b8408583b0083cce7658464f84514b90118d883010209846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5830aefffb86092c3774bbd1581d7e71ea26b38f2f4de6d580ff670aba62f71c6e094b63036abe6395bad134565f8eb8270f9804103040c10fdc41590269ce308f9e8661508bb5dab508301293dd74d67f84730a757d0d6cf40af83a874710ccc86b9dd454f5af84c8401e0ad09a0730818666625340db7721fb7f13898c285a181296cec9d5067e8330cf718bf778401e0ad0aa00a63bd8cf08c87d9997431a1ae783dcd41d1fb6cf1af6102fc28af56a12a5bd2804c785824a33b73ac319109c3661f5097bf414c5b2e69cc8a9689c9de33f1091707c45a85d484c0ba14f450cde783c70008fe95361edb14e4da27a0afb6ca59db00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129d060a9a06f90317a0730818666625340db7721fb7f13898c285a181296cec9d5067e8330cf718bf77a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942d4c407bbe49438ed859fe965b140dcf1aab71a9a0158b2961e6bb5d3d104f0ef414c5f79e43b2ee5367fa0c6af805af19ef4afa98a02dd5e26f41de268612fd00ccec1e30d5b52c2839812cf44b449be5c525b2ec1fa0eaf6b84b35ee86382ccbe6cb8981ffb6ad67b38b3efeda5d59f65d5955d06cd1b901000860624881023170fc084444809281224e08020220001000c022050040086240a000128120401408002009e00122023043024e0801a2233201200aa800244280241401059140402801b1801980b224b020144b200144ac1202468408c0248c80514800611a0200802c18005ae9284c00c80cc5c30188146832804b1d8588618080c88460b600a2402a980404c0e0208a0524d5b520208c8981900c50801000bb020329021345004012180040ea911000c00c900422820341432660292708891048200c02009001460a010a0a009832602640610110d006161190603a0c02e04041180221015ce10c03161e0c0350010040a00c4000e0484814014e94652b0007028401e0ad0a8408583b008377f4d08464f84511b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5830aefffb860a34d923feed7efca4b44deb27df5b7d2430584d23d9cfb542a1c36708f8b07b7bc46509f28ce3c295a1c7dc615f2643d17d987d62cda7944c5fa8ea08c3aaa4fab98b14d09224d0d85cbe57f821a0d2406cd6dbf7b0291f62cd3c4a3cb55b5dff84c8401e0ad08a0fe6f80973798f393ac93aae98b9836139de8e3649e95912b05ccf87443fedf928401e0ad09a0730818666625340db7721fb7f13898c285a181296cec9d5067e8330cf718bf7780a3427618abc9b80511f92a58e6df0f788cd9d561beebe79b8f37926b818e95f708adc7baf9b044dc947953d5f1d9c050708bd22b48bcecaeb881b57a3cf47c6b00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a05108ada820f22951df90e92f90211a06aca57d9a95f6a70fa1eee498e0b921d9534e7415073f2ac84751decff49adeba0962f40dd4801e1d7a03686701e348ab2443040b91f3f3db240de500d5789bd7ca00bbf300d1b67d2b495326bdf2591fde85cba3cb79ba931961e04965c64ea76c6a095105bbfda77162af3cba1815d1ace734c7a8f354cfc3027fa085648147bfecba06eba933be63aaaf45b95e24c0d8d048631ada57b05b41c35ff8957cb19fe430fa0c14237e60a406cec8ef20401b1cbbde444d9f7f78702ab1a663e86180895024ba08b8815810d3d588498241569d35c6d320fa474a5eebbed9c38b2ff40f2ed4791a02588bfaa39856633f34444dceeac1b9cb11e92f2c12db2cfbf15b1c936614d80a0ac203db58516b2c859bf35e66a83f50090162c68c2198c84c44850689e246bd6a0f3e6832a5686b8458032968437a37dce8511c3abe1ad41a5eb11bce7d7526139a0db8a9bbe33047581d4a26e17879bce9d3bcdd1b07a8ab3a89c9f1a5031decf7fa04db3342f89f97af398330b243a01e3c8da28c2f26dc25d8b867d5fbeb195390fa07b37f5fcb95aa83779fb66e5dda6a5ac05ddfe63818d7da5c307e6b4f742329aa0fc2dcb299dcbb045b5a3568a8a2b5d6cb47e7b48629c5ca8ebf873bec3b10e4ea0435cc1287ecb313b25b17c8e4b603811a1b421bb7d388a637ed8a35bf8142748a067ab05cba3ccfee894700310e9c2523a72a3e1434f3c9ede473e9025ed70115280f90211a0f1d95ee8f59c702a41510486db24528508f5d50d9fd55ad11f78e0c73b39da73a0d074c192f1be990b7efccf4c351fc06464007c89307b6e5191de3aae2a6e89b9a058b10102cb490244f93e2dc0e27c3e47ffdd18f5a2438f3816cdfe1bb2fa07c5a043ff4f4588e0566ad6d8cf83d5a8d09f6ce556d0c8d22a8b02edf80ac0f17ebba07ed65b3b1829a1527c2687c56c91474d4275b99111f463582bfbf7306e2e8c24a01d7076b7ec3586a681799d7b723373fae78a681c268093c6a6dab28b4fd58825a0d4ef40ebe7f01c0fcebc5065ffb851a142ff4627e8413a8fc49607420699f74aa09f8081487f5294ba9cad62ba9d2f5710357c317e6868e564ca9c386b3d5a57f9a0e4672f1bdb0dc0b8019099be16d66c45c20b3858ccadb5c17af97b0ed1cde31ba03054f4a48aed090fd4b1617c41d4625c10cbc831a8c11017b86ffb65c854eac4a074ceb17f5269b72d7de0e4b359ccabecb7b54e3babf40a070bb40df41c3a530ba0664da96a9312f3712efd138164cf4a83c67a2c55ba88446d22f6f2c91b2b26c4a0627d4be8da2d39c5bffc14c9a601b362ed368a1f0ae075cdd3957d82729d8b0ea0818e0d22bb0bbecfabd4a74649e5c517e4410d669cccc4e1da7df7573b318e02a035c709f509feccb4f4fc18577d378164b8bcc2040777500e7f3b19d73dee7422a0e4d7a464cbcfa3946df12a2b665995d6a5a4e2e6f7109671034da3b6e27901b880f90211a01a49a1b4be88a9316ec7a8033372e6ffa0551123140d061c3c4441005bf080a4a083554776499cf4ec35537c828481caa05f402bc9ae3645947ea70b9167290a5da03240202cf850c7da06cf8da2426d0efdbe710a1e6c802957f0ab4164d539df36a088cfc14c6cd4baefc5fdbbf0e6c3c0b6d3a86967bc88f48ec7f70b304ff22c5aa00883632bfbb361f2692d229af4bdf9317634ff4655352a75c657af34754d93ffa070faba82c25efb1a2c4993e7560487dcefbf3ffbd305b9c138224e4988e0e9aea02c02dc5391b9e5883454700116ff7eaa5d85c3bd9664497bdf098047de5267cda08f6f3af703582fcc83576e2ae77564298af13f7136411345476ba5c8e4f99762a0fbe1b9e22da392035f93fe58e1e98d9633df4f54ef85b04539866b79d16b8d8ca0c32bd732b64686e45bade850b6bcad854bc793b64a62b4e9d6fbfd411dab0fc2a0265ebdf24e23becf8cd2c9443514a319bc4b49442864972d322e1724263c8b04a0746580622ed7849d48abf26917b941ca703836ad5398fe9194e4041b5dc25939a090c88d844d393969e568518bfcae9106e3a1284fd31d35031b2b3ff82081c6eda0dd966623d8d06a2d812ddc75de6c4c660a2f157945338ead6413df47a97243e0a08347aa6659cd78803f7f610a991d5298fb721736e90765030d4b9fec026fdf68a0e511076b7f934c1b61614ab0801cf23ab1fe80c9af77a1a9446afde1eb35855680f90211a0ec935c90bdad6782f4c5a35a1965b65c5f70218d16c29104385a63c9729e1385a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea08c29f96efc5cc63adaadad0e4b3744f3c0885dcdee2c02fd40583185f6e53b7fa0e811da636688809cdcb2112b8dabba6e7f574fc6d5e15de5d822cd56df61b6eea0cbc367ca405a383f79dd4d3093ec402971c3247b1ccdae582f9a3367ce725d41a02ea9c9b7cb3dc108825dbbd6741aac718f8357e702066d809e066a4b3a4bec81a062596f5ca345da25d8dd053e1498f774a36b6453d2fce415a2a9622e424b7915a03930a8efca0e9cff8d775129523b348158b6be19c64e6201ed2e00812d752c2aa060d9a577ad51e91831e39242dc4ec447079c4fb7e60efc39a95c0074566a0608a0cef11c4a1546b3290a0fbdc52d61702fa6165e955f5f09d7c805ac0ae62f33ada04c23de558141ae2fcd7a8552780fee400810856552806171182b00e0a479209aa0029860ea6c14310da2fb42e5060f5321a4d013a8c8933703dc81ce5d7aa217eea06468be54e7f91e5dcce65d37e02f795cbdcf46da42e10d6637c58f9a67c69768a0d5695e93bd41511c59720f1a3fa0495a15a3836d61db770a0b3e64b437c92fbba0ef10590caccae23dc846a86c2500f9af0b34d98068566db1f59a32dc78d5bc35a0f96f72ad338d3b137690f64ed7e415e20a4bee181d40c52f49beaf5b92d3a98180f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a0bfe5ac7b3ede31763437dbbabf98627676721edea9c9f536c75cd8a705905e48a0ed9b9413f89286332c3dd5e7047bcdfc571e14a5345e74b727befc02e612ad49a096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0e55f099608e15b325b384739e6c25bb68b46a4ae5629bf33c1767543e2d14ddca04f3ae8e50f70c066723b2208e8330af99fa42a0fd764c88f40585c1948648a50a0899d9f7f4b3acc15580275d4444d4de5604a9a31bf10abf52c0729d30d2f9c4aa023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0f25a9512ef08c3a454652979cc7fed48a54e35fed0de36ebcc85ed0be8fe2ffb80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a4435ebb5849518aff370ca25e19e1072cc1a9fabcaa7f3e2c0b4b16ad183c473bafe30a36e39fa4a143657e229cd23c77f8fbc8e4e4e241695dd3d248d1e51521eee6619142a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b32440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9132442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab0324435ebb5849518aff370ca25e19e1072cc1a9fabcaa7f3e2c0b4b16ad183c473bafe30a36e39fa4a143657e229cd23c77f8fbc8e4e4e241695dd3d248d1e51521eee66191432443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a324461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b").to_vec();
        let height = 31501579;
        let trusted_height = 31501578;
        let c_epoch_height = 31501400;
        let target_validator_hash =
            hex!("eaa4be25e8c4aa9549e871201ec3f0a225b0e9ccd671a84953bc52fef427c507");
        let target_validator_size = 21;
        let new_validators_hash = keccak_256_vec(&[]);
        let new_validators_size = 0;
        do_test_success_update_client(
            header,
            height,
            trusted_height,
            c_epoch_height,
            target_validator_hash,
            target_validator_size,
            new_validators_hash,
            new_validators_size,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn do_test_success_update_client(
        header: Vec<u8>,
        height: u64,
        trusted_height: u64,
        c_epoch_height: u64,
        target_validator_hash: Hash,
        target_validator_size: u64,
        new_validators_hash: Hash,
        new_validators_size: u64,
    ) {
        let any: Any = header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState::default();
        mock_consensus_state.insert(Height::new(0, trusted_height), trusted_cs.clone());
        let epoch_cs = ConsensusState {
            validators_hash: target_validator_hash,
            validators_size: target_validator_size,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, c_epoch_height), epoch_cs.clone());
        mock_consensus_state.insert(Height::new(0, c_epoch_height - BLOCKS_PER_EPOCH), epoch_cs);
        let cs = ClientState {
            chain_id: ChainId::new(56),
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
                assert_eq!(new_consensus_state.validators_hash, new_validators_hash);
                assert_eq!(new_consensus_state.validators_size, new_validators_size);
                match &data.commitment {
                    Commitment::UpdateClient(data) => {
                        assert_eq!(data.new_height, header.height());
                        assert_eq!(data.new_state, None);
                        assert!(!data.new_state_id.to_vec().is_empty());
                        assert_eq!(
                            data.prev_height,
                            Some(new_height(0, header.trusted_height().revision_height()))
                        );
                        assert!(data.prev_state_id.is_some());
                        assert_eq!(data.timestamp, header.timestamp().unwrap());
                        match &data.context {
                            CommitmentContext::TrustingPeriod(actual) => {
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
                    _ => unreachable!("invalid commitment {:?}", data.commitment),
                }
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }

    #[test]
    fn test_error_update_client() {
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212dc400a9d060a9a06f90317a0ae2eb657c42c1d39d14be58f342763a6faa38308a4b11544261bb8e541b942d7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a00000000000000000000000000000000000000000000000000000000000000000a0afee1564e093703ad6f87cf673f26a72ab06bc7109388275df956d2e975ce338a0bbcdb674e55b324d1616abb6ead742b20a49940a5857e440a18600cb7c8a1b22b90100063a2254a8e2175bc1033964c2381703961bf294a4883190616f455a50709f108386736540031832532828c7d55f1194bb0d541ebe0a07210141210311343798f6c4a61183554da2691260398d2265a8bb7d80fb417b5810d0178140d0091f80441c1d272a57a443365b1083f112985abd08c6749c0bc40234210335ac0814300608fd051332f15a0682049878109e2f71346481690d194d8808dac40a82c83212ca02847264e344070096460e840512782400b12d874283447317f6ea790b396fa59493c2124ac6bc91c11152979121aa45364d2481003c0111570a1d56b8cab0dcfe53b02123b66b515e850801e184586c18ea48234778d70002281b7b2c48028401e0ae5384085832a783ba2c778464f848fdb90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831befffb860a9e1224ba9f2eebfb307ff11ee982fb9499576e90922622a06b774dde805bdefc7145793e39745438f735fe62416023902288ed49366d819aa2152ebb038a01db6453ad266f921ba52351dda23403feab385b63ba360d246c40fb932d7f28b28f84c8401e0ae51a0835bbc2764604343319d11285308786b45575e82c1c63af8ca7d28d0464ef6598401e0ae52a0ae2eb657c42c1d39d14be58f342763a6faa38308a4b11544261bb8e541b942d78094e8fb06f52aa5f90021732bde806abc83ac3c34e45570a01038602572d47944046b53f6949935b8c3be1b48143281f8dc44a9a9451332037224ae86143a609301a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a0835bbc2764604343319d11285308786b45575e82c1c63af8ca7d28d0464ef659a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d1d6bf74282782b0b3eb1413c901d6ecf02e8e28a00ca9d704cf17d7bc81ef47d2b6d4ec577e537f15a432a35144164a3804306542a0501f6e232b649e26df581d5a959cb2f5584c90ec8b304dfc26cf789643ef38b4a0e61c363f51b8da659e263b8f55bf5178513de375959e2469ad2571b0f6e26332b901009e3b8b9ba673f59b0e5027cff4221cd3d37b545ab78baeed13dbef6f39f2af9bee5373224644be7cd7acbbab9e76f863ae1de17fa1ae79fa5b56698bfb2cffd995f17561ebf75f7b5798edbc629b3d2d32bdf9b727e5fad696dfd169e6d8fedb4dcdb833cb47aabd89d4d15a794eeba9fd54377b8f6e7c65aa61f4540da75e8849cf4c2fde3f43e7d5cf6e44eed787dcf2b46e8df922cf9cbb896573fa9e7d396beba82fcb308ab58b08be243fc0e5db94e796c6b5da9aa9fbf9756be04190afd2babfca631d39477f7536dbf7e2f27abfd7a848a4886d3d29beedf7f62afd1037f0c60517ef7b16dfb77a426023d10969603dbee83d467fdb97096f292974cc028401e0ae5284084fe2c684010d99158464f848fab90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831befffb860b8ed0cf5feb2d61f19a24b55e48dd70187b60ac63ee1d1a923b74cd55e6f00f53725cb44709d16f4186dbcfb5fcf92450d206107e076bb565ab1873a92d597bf52fa1bdb20fd99f82a1ac0c70c3ca85661133c75dd58212db42657f6f4e60182f84c8401e0ae50a0d1e8d1c5c7a5ec30c40ce5e4e8d7872e27f86db89460ab769f6ab58a2d657cc68401e0ae51a0835bbc2764604343319d11285308786b45575e82c1c63af8ca7d28d0464ef659806931acf461528eacce842768a537beab5a0581d71b9bc3a6ebd27757c3ca11ef2e32018fb07f9f33f855fe2aa2b610eb63c80075c1d34e28e315080bac7b1e4000a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a0510d2dc820f22951df90e92f90211a0dc204d5e3e58ec3848993dac30713312d2a3b4ed4c71b5c20675f37cb87b2b0da057c16f82d006a5847d2ef0b47f20cae7205e6e2c4ded31517c9af4986356e27ea070362bc58914e65a257ccd645d2a0bc88b91197b2bd988829b78be33e5ecc1a0a0782e0d02d41a3b2007da7cbac74e978807b9c52eb88562b86a8fb3a711cac27ba02b0c7d9f2f18c0c11e1375dd99b0a0ed15a9a6d210618e79fea7718e125b1e39a08f8a55731ed53071a2eb20d95b20fe5f83b92db35b8e8391c47ab35082edbfeaa07fa8263c7f893c31fb7c124c9d60c693812103d228154cbdbac3ab4b3c3d1653a00016e8dd3717fcbc0e4d75defb9017aba2d02e282434d3a43b726c3d2b3583bfa010e0af3ef010128c844a2ad977a7ca02340ffe82fe8f948372401657ab2c12fea0f3180f485bde4887014ffe54bfd9cdb639a459179bc129468551cfcf0e7cfff9a09bf7d5b7153a249aeb7a210de6e493d9e4f13aae0b0d526012b705ec9d9cda1ba0a68258244e7013928d48e07d9adbb4f4ab9ad738a6134e781afb05bff47ee0afa0a60e8f6070c7553d6f94bdef2e355012d6c78e5a023c9298e49bce42e02e34aba0e42406536949c9cff33f5a81cd3379980499c75cf6bf9a50e6fe66ab5e0a80a7a0bb31c4b6703ba9e5e8630647bf5074bb229d8a7ac45709a97045cdb62e3d1c6da0c1d26950f52187eda1b94fabe8e6b33db4fd911ae25905d06e4c56b2f3e13d5b80f90211a0f247cf287efc56cb8fd3d4ed450ceceac5a0140f751ebdb4bf7bdcc30b654471a09d58de5289a34344020f31c7a253a463ce76f3cb387d0c70ebe3819bc50d8effa073c189560f39702551ce0d0f4f6a89fdb5fd7d8cf716ea8c04355061529f6960a0a4084b5028a1095dea08391734e7edac82fcb16916ac1985285a8cd79f925b59a051937e6228ff3e68c6f3b1a8be3d73b014dffd9af285846aff4f14e5a9dd72a8a02fa566eb31f51b220e9571fc599b0ef3c683ea74d4120536f27d13fb6287991da039fb64430965e407bdab3d56849620dcbf698a5c39f64c709cd82f49afc10945a0ed6e0704151bf9448d9c410eadde1ffe2481501f785c19477bfe270e186b8df2a0ab84577f0602220106d73d7cec1d51a891dc7ddf0c4972038b49b17cd561db7fa001de52c30847a8176a9f5f2f0f8e73af34fa1fc08f9589e8cddb538c142d2720a017fb393ef2c058375ea25c2c3c3ff07db125da2ba446bc502b596bc8e7a6b73ca0227e1e02d6df86cefd53e43d402bca27e760ede5471b8c116d74f3ea47d46695a0f22ab19d5e99321c1e0093de661873480d52b5cda52c8a758e716e328af11392a03bab46b60c5d97183140f6dfc52b55cf839348d007f638eec70f50f0ec628383a0b8a00f9d16a3a40a1ca7c9ce77796500b8cf2e3e552266e1008ae03bc6ebb887a0a93f2c7f58d11668e62e75ae058bf4dfc5780fea8133e562209daa08bc29271680f90211a05b9ec8fc295d36e4e270ee06118a46f6061d176e0cb8785245dbd849bb6f0c09a0cd884d1673628be328b009a157090fb3714403421866b02ddf27825ad458bae5a0c943fd09f8d5d005a0bdae4d9bc331327f9ba8bb8f8a90e7cfd1fd188c627553a074bc4f6da6672cb6c71d4a440430d6affcb1675f1aadfad9670b739097fbef90a0d46506d26c8c4bdd717c139e179e475c5e78f935e2c0796a477025ebb27313fea078b8e0157299694d36d63dba51c46c0009bcaa179739e3521ffefe18f026aec9a0c8a9d8e7298368a7c28cc5b76d996dd78afcd78e892b8b60f3434fbc98fd25afa08b95efdaa7fd3bf92f43969a4827d3e4844f03decb4856073206991f00c14c5da082ff9a65875ea2996d0c8bbe67d6440fb3f95dfb5a7969377769e3d1b2f853cea02b72857007402fe5bc9be45855687a6dd34e97bec4b88647cfb712303978d809a076703fb96e9d58f03257a4fdd4ecc6100ca9c8c03b96bba5aaf04ff0a93bf21ba0b6f342c26bd5bcc2ad749ebd26f6d3bf3ee1336f301c71dc22f865716eca662aa0aac8a1cc8e06a2803ee521011df24b13821eeccb0debf17065c61b2d67ec63bfa0227b42b8e10d45f7c5f5fd1887be16e284c379fc6c54c8f41b57d41f64a16e73a0cd839365e660f61e7bfa508e30d228a3666793555683131a3f225571e4d8506ea067522f6fd197aeb4a00c907572e2864b9c0c2e50b765455c0e398cdaabaf066c80f90211a090dffbb63fe345a1b2b2b55133c07263b2c077159a340afe1e330b419fd57fd8a0f0163a203d982d624281312122c30916bf498072335ce46f8f62d5687e78d7a5a047ed0d2ecf2c7a1d52232b5d4045b879edbc9e8d88fc36b6e1d8f5210804d339a083a189b56cf88c4c423e5f850ce47109d1ed142e556694c343b6970f5a3637e8a0a083d8a978629fccc7ae139f1368964dbd341b650e493451038c9f80fae93b4da094dc19f2d0bf8bea03470dcd8cd01ad17e0b6b83a29cf4908c74d31ddf91d82da0cc78c54d30c25ad38c8c2665f5f1c2b9ab508b28610bef5ff76154be2c88d41ba08231468dbe97eead636dd0450e3c45a57fb51b018a27705d4ed437efb1502ee1a05bea5b97efc03dcad20b425f7ef66787cdc9ba89aa2a464c55c6f99495872d08a092531762db54a98a84223046669cdddafa5cf3fbbc4a3724e3474d2b5f2a30a5a04c23de558141ae2fcd7a8552780fee400810856552806171182b00e0a479209aa04c7a680aa402da009ddf03ffd82dcfe94055f6ac8beaf17a566a1ae211dd04eba06468be54e7f91e5dcce65d37e02f795cbdcf46da42e10d6637c58f9a67c69768a077495653802f98ea3f9868d5e3b63f972cda1c7e1457f07a6125bf8de6185676a0ef10590caccae23dc846a86c2500f9af0b34d98068566db1f59a32dc78d5bc35a0f96f72ad338d3b137690f64ed7e415e20a4bee181d40c52f49beaf5b92d3a98180f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a0bfe5ac7b3ede31763437dbbabf98627676721edea9c9f536c75cd8a705905e48a0ed9b9413f89286332c3dd5e7047bcdfc571e14a5345e74b727befc02e612ad49a096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0e55f099608e15b325b384739e6c25bb68b46a4ae5629bf33c1767543e2d14ddca04f3ae8e50f70c066723b2208e8330af99fa42a0fd764c88f40585c1948648a50a0899d9f7f4b3acc15580275d4444d4de5604a9a31bf10abf52c0729d30d2f9c4aa023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0f25a9512ef08c3a454652979cc7fed48a54e35fed0de36ebcc85ed0be8fe2ffb80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca2a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf92a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b32440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9132442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab032443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a324461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25324469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca324470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba7324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf93244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b").to_vec();
        let any: Any = header.try_into().unwrap();
        let _header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let epoch_cs = ConsensusState {
            validators_hash: hex!(
                "653e49fe3926a105d463afc22d6b5cd4e3b037893525dc8e57c14ffd0b01f0f5"
            ),
            validators_size: 21,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 31501906), ConsensusState::default());
        mock_consensus_state.insert(Height::new(0, 31501800), epoch_cs.clone());
        mock_consensus_state.insert(Height::new(0, 31501800 - BLOCKS_PER_EPOCH), epoch_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 31501907),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert!(
            format!("{}", err).contains("UnexpectedCoinbase: 31501907"),
            "{}",
            err
        );
    }

    #[test]
    fn test_verify_membership_lcp_localnet() {
        let storage_proof_rlp = vec![
            249, 2, 108, 249, 1, 145, 160, 243, 2, 132, 113, 118, 63, 160, 241, 161, 149, 174, 195,
            18, 210, 53, 140, 244, 55, 106, 61, 135, 92, 126, 3, 174, 227, 145, 76, 246, 158, 163,
            237, 128, 128, 160, 161, 243, 110, 96, 138, 107, 213, 87, 172, 13, 123, 131, 19, 176,
            84, 242, 32, 18, 219, 20, 61, 136, 234, 214, 229, 63, 3, 59, 48, 2, 150, 137, 160, 175,
            166, 191, 1, 133, 187, 201, 138, 8, 129, 81, 61, 81, 86, 33, 87, 198, 100, 189, 6, 230,
            101, 136, 66, 66, 242, 24, 147, 184, 24, 61, 33, 160, 23, 83, 180, 210, 64, 112, 1,
            189, 122, 120, 147, 18, 45, 252, 211, 143, 177, 16, 93, 219, 135, 216, 71, 156, 65,
            241, 141, 38, 171, 247, 237, 182, 160, 210, 143, 238, 182, 140, 97, 22, 255, 66, 68,
            225, 250, 55, 56, 89, 201, 28, 147, 181, 102, 138, 47, 37, 0, 189, 189, 203, 212, 152,
            186, 241, 212, 160, 93, 33, 126, 80, 5, 168, 58, 116, 140, 187, 49, 219, 74, 219, 118,
            193, 62, 119, 121, 235, 231, 13, 122, 189, 163, 187, 122, 145, 6, 196, 148, 3, 160, 9,
            226, 194, 151, 8, 9, 20, 134, 217, 158, 89, 5, 196, 34, 23, 235, 234, 182, 193, 155,
            131, 238, 116, 100, 192, 196, 214, 102, 88, 180, 15, 239, 160, 114, 77, 73, 24, 57, 36,
            101, 1, 166, 27, 246, 128, 196, 20, 105, 243, 251, 51, 205, 247, 112, 2, 4, 109, 93, 1,
            104, 71, 100, 138, 24, 237, 160, 209, 8, 0, 140, 126, 171, 172, 12, 93, 82, 67, 64,
            234, 3, 152, 165, 245, 137, 166, 131, 218, 2, 177, 29, 84, 166, 186, 8, 42, 245, 54,
            145, 160, 214, 233, 118, 109, 210, 194, 72, 219, 143, 9, 216, 125, 95, 190, 129, 254,
            160, 111, 112, 122, 146, 103, 213, 223, 119, 10, 156, 212, 4, 60, 116, 180, 160, 90,
            98, 164, 183, 88, 177, 161, 231, 114, 25, 237, 70, 112, 69, 253, 90, 125, 202, 100,
            255, 155, 200, 174, 225, 111, 199, 221, 194, 180, 124, 109, 50, 160, 39, 152, 155, 234,
            177, 15, 57, 47, 67, 85, 70, 121, 225, 22, 86, 184, 135, 250, 224, 143, 245, 81, 251,
            117, 185, 11, 128, 32, 154, 54, 102, 126, 128, 128, 128, 248, 145, 128, 128, 128, 128,
            128, 160, 103, 18, 133, 119, 55, 115, 130, 213, 70, 76, 86, 39, 144, 246, 223, 29, 254,
            134, 177, 180, 108, 75, 102, 200, 241, 205, 231, 206, 19, 221, 182, 244, 128, 128, 160,
            111, 93, 78, 118, 145, 122, 232, 53, 185, 114, 80, 95, 148, 212, 14, 218, 218, 253,
            220, 68, 46, 148, 77, 193, 87, 179, 71, 171, 145, 93, 173, 118, 128, 128, 128, 128,
            160, 192, 156, 224, 147, 42, 238, 11, 71, 160, 213, 233, 164, 59, 206, 68, 79, 86, 159,
            212, 42, 109, 164, 91, 77, 164, 86, 88, 8, 192, 152, 241, 183, 128, 160, 8, 21, 54,
            159, 64, 208, 81, 17, 118, 220, 29, 163, 73, 142, 1, 7, 9, 151, 63, 23, 186, 206, 165,
            2, 3, 144, 30, 15, 37, 48, 164, 148, 128, 248, 67, 160, 32, 63, 196, 45, 223, 108, 27,
            91, 178, 24, 206, 36, 225, 76, 64, 175, 158, 14, 177, 39, 165, 215, 96, 80, 211, 125,
            115, 105, 226, 252, 74, 71, 161, 160, 34, 171, 87, 106, 125, 243, 139, 180, 134, 15,
            251, 198, 95, 48, 213, 166, 101, 54, 251, 45, 142, 195, 213, 215, 212, 171, 154, 62,
            173, 14, 67, 18,
        ];
        let expected_value = vec![
            10, 12, 108, 99, 112, 45, 99, 108, 105, 101, 110, 116, 45, 48, 18, 35, 10, 1, 49, 18,
            13, 79, 82, 68, 69, 82, 95, 79, 82, 68, 69, 82, 69, 68, 18, 15, 79, 82, 68, 69, 82, 95,
            85, 78, 79, 82, 68, 69, 82, 69, 68, 24, 1, 34, 21, 10, 12, 108, 99, 112, 45, 99, 108,
            105, 101, 110, 116, 45, 48, 26, 5, 10, 3, 105, 98, 99,
        ];
        let path = "connections/connection-0";

        let client = ParliaLightClient::default();
        let proof_height = Height::new(0, 400);
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            proof_height,
            ConsensusState {
                state_root: [
                    51, 143, 168, 48, 229, 178, 255, 245, 35, 4, 82, 182, 21, 136, 15, 201, 229,
                    227, 54, 146, 158, 189, 229, 10, 242, 165, 205, 60, 170, 52, 212, 78,
                ],
                validators_hash: keccak_256_vec(&[vec![
                    185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136, 133,
                    3, 78, 91,
                ]]),
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height: proof_height,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        let prefix = vec![0];
        let client_id = ClientId::new(client.client_type().as_str(), 0).unwrap();

        match client.verify_membership(
            &ctx,
            client_id,
            prefix,
            path.to_string(),
            expected_value.clone(),
            proof_height,
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => match &data.state_commitment {
                Commitment::State(data) => {
                    assert_eq!(data.path, path);
                    assert_eq!(data.height, proof_height);
                    assert_eq!(data.value, Some(keccak_256(expected_value.as_slice())));
                }
                _ => unreachable!("invalid state commitment {:?}", data.state_commitment),
            },
            Err(e) => unreachable!("error {:?}", e),
        };
    }

    #[test]
    fn test_success_submit_misbehavior() {
        let mut mock_consensus_state = BTreeMap::new();
        let epoch_cs = ConsensusState {
            validators_hash: hex!(
                "5e79e96afa934578b18fcb7409b2d81e6ae2c29788bad97cc83065b71c20d8b5"
            ),
            validators_size: 3,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 402), ConsensusState::default());
        mock_consensus_state.insert(Height::new(0, 400), epoch_cs.clone());
        mock_consensus_state.insert(Height::new(0, 200), epoch_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: mock_consensus_state,
        };

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // Detect misbehavior
        // header1 = localnet, header2 = localnet(9999)
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212ed270a0b78782d7061726c69612d3112fe130a92060a8f06f9030ca0847c7603935afd79e17555d67c084f78354b2c791f3ec5d0f75b635d02c7c558a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0af27b91437f89b6cc11d8d2f20ea028feee530b30187bbfe7f0e1d8dd75401d5a0ffcd163108c5f2999a0ff4666ef22dd0b6e4348a355510c53eeeffc7204ca699a0f029c89d8df754391ace15a8995311b0e927ecac380b53fd8d78e2bbd69928a8b9010000000000000000401000000000000000000000000000000000000000000000000000000002000000000000020000000000000000000080000000000000000000000000000000000000000000100000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018201978402625a008280a58464f83741b90111d98301020b846765746889676f312e31392e3132856c696e7578000091462fbdf8ae03b860a3522d8fabd971b3c2b429ef987a42c24c4ba3c23f8f1c9016aca3526307d44ccae48126ad6905af04db95eeaf0a1ba80eea30b1ec44f9773452a20e7995b4daa3aee89919fea287fb33687108ecfedd408a8d2677ed93e9bf094c270fc6a44af848820195a08a62bc672386c2533accf5c8fe55aaac473bc84b45839e2fcbf82ee0de4880b8820196a0847c7603935afd79e17555d67c084f78354b2c791f3ec5d0f75b635d02c7c558800862c4d96dc0b488241c5d9e87b7c8592491a91f890362206bb8f4d082879ad25786ea7bb85af2bd395270eb21f627a18c92b58cb554893344146ccb585a60f800a000000000000000000000000000000000000000000000000000000000000000008800000000000000001290060a8d06f9030aa08a62bc672386c2533accf5c8fe55aaac473bc84b45839e2fcbf82ee0de4880b8a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a0ea250a1fb482e598e507cc2144b74b1def27a1ca8fa53a19e6333cb15c92c670a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018201968402625a00808464f8373cb90111d98301020b846765746889676f312e31392e3132856c696e7578000091462fbdf8ae03b8608b5b6ffa4790644a489389dff3b37aae57179d14a514ad21ea0a40881cccd772bf568320298706d043ed20141a3b17f80800dbbce274fe9c9f5c80a7950df3eb5eacd59b5104b1443dd32743165254f062d336c3048ab4e303bd36354d309facf848820194a02627189d9af6103ac59c343e8f58b826ae2ea85e1380fdee489e88fbcc9e644a820195a08a62bc672386c2533accf5c8fe55aaac473bc84b45839e2fcbf82ee0de4880b880b316107cd7ca91b458efbedfd0a7fa394ce131bef3a26c8319218ebb710e088e64e8f5cd7a7dae4e156b0dde41a3492180d30e629b56ff6d065f48b457b85a4501a000000000000000000000000000000000000000000000000000000000000000008800000000000000001a0310920322aa04f90227f901d1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a0af1fc6dc8aee0de1c4844230d31220c33798d54af180037b2571e6be0c935ce5a06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a562a0ecd6d7b6402cc92f5e97af7bcf85f002cf3e81a6699760ed57fb759bd6eda9a180a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a01b0b68670bf896b2a1c4709ba844519a036b49d2d7d3811e1dbc7b208f473800a0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a02a762ec45fe8909bc01a19dd882862342ff76765597fdefc27b1577b8eeafdc6a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a06e17e34ff3a3afaceda8cbb41f832adad3563a0f1874bd34bb2dc836f3425c1380f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca808080802a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff32448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2073244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72513244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff1adc130a90060a8d06f9030aa07ebbd459da4876051588e25eee8ea911c25f4a6757642877c422b2f337d25872a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a0e34b69f6a483c22ef85bc8afb78a6669c4bf22766f5d03be613e39480bbaeaf6a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201978402625a00808464f83627b90111d98301020b846765746889676f312e31392e3132856c696e7578000091462fbdf8ae07b86081f679751868a7c2a6bc2e8f697de6ab3f76f5a286a5d046be4912aeb82763b303229176a69513486338050743bf316b0242ba56cd651962ce81410544eb80b4f86e0ce8aab2a4621798a724caebdeb594e9fcb2d08e1670e25b6d717d47aa50f848820195a06bfe755a290bd46c2e82c7508191ae761b6fa687400e472107e9507dbc456c49820196a07ebbd459da4876051588e25eee8ea911c25f4a6757642877c422b2f337d2587280ea5f126a2501d787dd7884f6c80943850019611a4de29730f3f6fb8dc8579e5007528e61ab60c3cd26e6dd2d04e3d57d6931fafc1f8de2c077356fe4088d171c01a000000000000000000000000000000000000000000000000000000000000000008800000000000000001290060a8d06f9030aa06bfe755a290bd46c2e82c7508191ae761b6fa687400e472107e9507dbc456c49a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a0e34b69f6a483c22ef85bc8afb78a6669c4bf22766f5d03be613e39480bbaeaf6a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201968402625a00808464f83624b90111d98301020b846765746889676f312e31392e3132856c696e7578000091462fbdf8ae07b860b5a27c7066630ac3ba2ab2a7fb91a4c09fb9ac7147c52a937bc2d694d0c97007a92e8b2f7dc1e14f442eb2d3c15cbc0c039b0618f9cb0dc0fa63ece87e201b15cd044f7a03503b1a4341e908a76635cc32fd8f2040bbcbaf72f9492ea0329416f848820194a042445a1e588454a1d15bee753ec7f1c3b319bb31635619073527e95dd487562b820195a06bfe755a290bd46c2e82c7508191ae761b6fa687400e472107e9507dbc456c49804bf92f3b32b43a20c8cd84ba58a83bdc15f0468da5d7c817ca82a3a4a6ceb752102bdadff3ce4f07eacadb9d44aab183bda3fcec4cd3533927b212fbf5b5add800a000000000000000000000000000000000000000000000000000000000000000008800000000000000001a03109203228a04f90207f901b1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a0af1fc6dc8aee0de1c4844230d31220c33798d54af180037b2571e6be0c935ce5a06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a5628080a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a0e037c6e526e8663afaeeca7a6446883d9c8023ac8097df105ec95ad2a494a53ba0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a02a762ec45fe8909bc01a19dd882862342ff76765597fdefc27b1577b8eeafdc6a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a08ad62b6962f76ca4a39f319e11e1f806e8606e50703c2636ecdb82643889042d80f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca808080802a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff32448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2073244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72513244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff").to_vec();
        let any: Any = any.try_into().unwrap();
        let result = client.submit_misbehaviour(&ctx, client_id, any);
        match result {
            Ok(cs) => assert!(cs.frozen),
            Err(e) => unreachable!("err={:?}", e),
        };
    }

    #[test]
    fn test_error_submit_misbehavior() {
        let trusted_cs = ConsensusState::default();
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // Exactly same block
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212cb81010a0b78782d7061726c69612d3112dc400a9d060a9a06f90317a0b4f747b591e55db4f7b2e63a4722729b61e8dc7016c8547574cb4e53a59b586da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda00f00637435df7052c2cc9d1c3209396f67c209f517a01cd5aa20aaea405088a8a0c14fd10d3ce45960f3dcb434914e81ab369f71b79bb003e98029ec0fd65485b6a06b1eab663232f2ae50be89e40c59c90a7f33d6d30b732352464808d23479da86b901002efbae4d77a91ede0845ded7a2dddc6f3e6e4a44c5939680398793b67bc4e11bf755dd2175fbd6996b66bd7df4be5305fbcdf9dbd62abfb66ba8a07061ac6788a67f4548bfd5090e7d7d354dc4e77838eff4d8a94757ca82a75e09628831548dec8dd0ef6e067fa50f4f7fd2a1c399d8dd078adb9f5b46abd6b4fedacd080ae02ddef81676fd18db92d92c5d7c02ceadd7af0dc5f935ce5b39cc14d958c08ef1a6f094bf7bbeebcb3e0ebbf46fc627d7c2e9f59eb89fd227bba384f07cfde947ed17154a10446d5673f2a4e6951f702d33c3ee7f9ad45416153374d33639fd4f96d8e56dd7d90d0b9d955e4761136145f7becd30d4bbe7696931b5b53e6d705f028401e0a8988408583b0083f825098464f8379bb90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5830d7bffb8608c6e38ace53b5b2e6a6e05d59d6d0ba732eef4b2d1057a7c71833d863cb43fcae300f07712995911a4b0c7f45de14879064f79924549f033ddb6bc90c6909abd6740669add66f6e4a0bf673ce8f8f14a727f92d28572b88c582dc40b80b55bb1f84c8401e0a896a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb72218438401e0a897a0b4f747b591e55db4f7b2e63a4722729b61e8dc7016c8547574cb4e53a59b586d80773fcbd7bdd32ec3aaa8f479ff81d83b2645b7c88129db2bba7f0472d4f7c29d40237f191ded0754213d3a3370ab127dcced7f9d149435ed945672326523b87901a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb7221843a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ee226379db83cffc681495730c11fdde79ba4c0ca062444d3e162738b70671774b4862687181d16061c432218e4ba7a461062cbf41a05d523c486abed40b55c62490f7e6c736a650e0063ae74e276558d76a6e79f2eca04264d8ba1510e7c04bfd868e0c363667adbbdbe522fbe1aca9ca70f0a0852150b90100cfefbeff7e5ffdff3ffffffffff3fffbfff9ffff5fffffffbfafefdfffffdf7fffb5bcfdfffbd3fffffffbabf7fffe7ffffdde3ffffffff37ffedeffdffdf7fde6f7ffecfff7fdfe5fcfb7cfebf3ddffbfffffffbf5fefffffffdb7dfbffffeeeffde7e7ee5ffffefffffffaf77fdfffdfffb8fff67fefebff37efffff5ffaf37f7fffe772fff7ffdfe4ffef77f66efff7f7ffff7bf7fffdefff9bff7ffdff7fffffd7efffff7fe7efff97f5ffefceffdfdfeffdffffffbffff7ef6ffd7fefffbeffdfffbfffffcf1ffbffffb6dbfdffff9fd7ffff7fffffefbbfef7f1fff3fffbffffffd7ebdffcfffdfff2ef7bffbdffff3ffefffeeffffbfbdbfffffffeff028401e0a8978408583b008403ca4f878464f83798b90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5830d7bffb86092ca39301248483fdc36d490add87d766f62c450aff74d50b53a405d5c1fc0fdcc91b34c2e29438bec0d4ba5d6ed1e4d062d145f7c9190296ecc43707f1493d3f988241f660a28444b514c382e76a4930d50b82ff73653585c927e6e6a4db1e1f84c8401e0a895a07c6aabbc3fd3162a0dc3b304daab5179fa314d5aa693de4ce435a74729caaf498401e0a896a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb72218438066a0258ea8c512cf9530befba8296fe2a03ef597d255a74467b2b8cd3c77154c630589c1dbaef1a9cd54b8890e49e53c26fa4ae5e19b3de47c0bbcbfdb6f58ca01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a051097d1820f22951df90e92f90211a021f47fc4c71ce28cd9e049b3fe9dddc578f2a00ed61497c5b37bcc8e48bfcbe3a0654bd8d6f686d4d76b556e5673a3c32e86fd50778395e6ab62057d8accda70d4a0b79f5c426a78768fde22592bf8dec67dd8248ce91e5b969e5cb17544b0861ccca0d38579ccb94ccd1bca4590cf67f95eda9525c1004c742d2c1f15d050a75e1a3ea0f2ff6f14155561435bf87b9918b1d49efdbe63ef6d3859ffc6779c86d0aa6a67a03cfe521867772edf9258062588e73d070767ec119fc450c076d42eb49848e736a08233cadd954be16be47323339280fa17d8d38b7bebe66e58263864579b9160d2a0934a0a9167d33ddc0acbfd578aa6456338905da0a57818e4fed4dd6bf904242aa0117adee8e08ab69c21c3d94509780b055ce76e9fc7d246224286812c14956be0a0a325680d542e0a681f14938b6e8dba2bb67ac47c7e46c97c1e1c5016424d6938a00a52321e954fa6dc9d18364f45aca50c63626b9c11a0a59950793b427dcdc0d0a034383e09f2bc0c053ed3e951ab7e48c7118c0e5eb5b5ff0a6f57c0c9a4c06c32a0a2a0b07c45834760874054d33fc50c93d387d325d003914f0c65bf1ac27fa2caa0d4f97f9df1f99d342fb9337923449f0d897f1b2c2d6816a344851c56b1fbd925a0c553d144a0b7803722e2b6e1f008c738511ead86be5b39bbb2362fe43216e2b2a0492b5c75ec293337ac1671aac36a12fe094f9d4afc85fda5256d008a95527c7f80f90211a01482083171a85db571e8039ba0943037b2dcf62cfd7e8883ea43414f5c878989a08115d92802a81c3edbbc3b4e13bd8238de6bbd4ec41fa153a9d8150c036d84bda00ef3abd5bd4c03ca55e95d04936b5fe26435ebddd9c4c3e943be1178e95cf586a055902ca0147733add5db2b9dcb408d7438c61ff0a9c2ae6909ae0059417cf705a0a43e0b400b6e421565416a4634e04f069620c921c16c4c834d6fc5428d78a9b5a09dc094626c24d80c45be99922cb648cbc97060fab6e96e4e80993707b2c52724a0207e7aceb06a66a1700ff5608dc84284b95861ae0b807832e37293ee10cab7d2a079d0faf911472c495ff5296f3f30b7abc343f3c7554f2d0a52175c7c37aa59fea0a5a1d6a655723905c16091f689b51b617cc9d6f61d4f9ecd95c7f661d158ecd8a0469cb57e4cb8fbf50ecb243e62430f00abc984cfd2f8d3e70430df77501cc578a0d802da49895b71d47c16d9888b6d22b441ac1be36a8eb191f1f3667bd6301722a0c546ee6ab96d5fb63b782dd661c1435e9132cd55b1ae0adf12528b9e2aa17afba074ed5d006f4ac02dbbfb606de833f7f48f3f355d2b10b6fca83558404ab5c3e9a08c387e90049477e89107bbc0f23f1e74fb014a1a56d5e0ec644cfc06e0de80cca08e0739e0e80255f982390cdb4333cedc812c7d8a8b2d28f77c95d40705301864a000aaf107fb17abf295f150088edbf969395e9f865aa7c3ea494217895fff88dc80f90211a08657cad2ea1ecbfc601fe1d75015454104d868cea76db854f5f97d5d3dbe22b8a013001952cbc7164cd427beed0feedf61d8ddf54a6056fc3af40a09482fb0b904a0f96a07a3b52c4f6afa3bc94096c3dad9d716048b67b65b9372ed28b84a7f867ba0d1a7533ee10ffe325420de1cf44e66e535bf3070ee7c7bc51602bc35b0809a85a00b520f0ba3709df2263da4eeab08baa259fd89d0794a4d9ad348bbd7b0bef2a2a089ccdb49ac55b3093681b1c06f909ceab578188cd1c911685eab2ed43eb81024a0de6aec9081b3b7a30e26d71d5377b47c9822159b83d7a98e724b96a6266cf537a09b78f22559d7437452123074e41908bba67f1519573809b90e0300340ff6c526a054ea73e9e553db21ebcdde46e116030f0950babf2289788ce1cd6376e1ce1962a0c50ca2ab183d394023a58ca36d708e9af9ec51946269b377b6af60fa57b5bcc9a028e5333c4317c4807523d659248fb2588748979e3534a33e15292fb80bfe7c40a074b67a93aaba82591572a303cc67018689b97a4ce911c29e9567c2cc53903878a0c0e0b2b7f493c904f378b2697c84288cf65f19d159ef12341094eea7dab53905a05c41b85be17e61f397c7e181b8a466cd05dcb432ff5e8cfc9b6ec7fe0513e35ea043503c0c7fb469703f24cdd95a85a20386883e493e8e3381701d82c25eaed391a0a553abff5c58523d28a306247e333641c0db2b69b2678cb9cbb80628a75d746980f90211a02b0bb937e80df96357496fecc9c2867c6d6bac3f8d0ce5ab4ebed12dddc27058a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea001075113e41056754193ec2f07875210f072c2f4af49af8f2ec17dbbb0c73959a05906881965c59aec1e32a5f7f2bcfb38ddb0c6c7ab37828a904cdaac2692aedba0a126e78f29bec0484bdced0c364a0f90ea15ce796746109b99a55b41947d8433a00f300df74f29484f4ae9535e6c04f6334405ea81e5080ea5d061778623804611a07be493f4e20698e147a967a3906267dee98e7fe1415d55e6e7302ebf87eaf672a01f879933e4e640e58aec28ce41e7f2f9e489ebce2df90904113e61c4fab69c7ba0a4ce58ab185d31ab35bf68f4ab718740253d27ad14d91ccacb6cc8cd7c7383aca0202ac97dfe72828db6083d55251a2c978ed400b579e374ad36e0375ea649d252a072eda53fafe5d4470ce7a9869bfba77708f903f350e8724576ebc059142e12a7a0ba58b5b506eedfa74a4f0163a657a100916fa7d3bf298bd6f355bca173776fa3a0eab5744b05399a419026ca951cafc64b9fe509890c38daaf4681bc51a8606573a0de3920cd5b33f70046dbcc501aeb61c419d80d751aeee6179fc0a8dbc5fc8832a0a3a7e5c873ca68a89ebfd2bc67252e20a99c2d409142210173d48550b4bf9df6a092dae397f0eade2f54af3a667b7b1a26b2fa7bd84ddde17b74a25840f3fc690480f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a068586e55fe196915ff1c0372869784268e924b37a1fe030a25f5cb174eb3f5dba0ecc75a220a887f2e21476bce8fc707966851c4894e3feba4083d53bce765746da096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0194e628edfc428c2aad974e6d95aabcc65dfe92dab754b85b7c29ce15f28621aa034680d8ce0716dd6452eb4d019bfaa5b3b80d93912d6f03b22630e3c0757ddc5a0e3fb01c5b7edebe9970d16a07c52387927acbe0be058476aad7e76b1285a90b1a023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0b749fecc509a19e4ba21e91be9cc2230945e28373c35addd3319a689e063735f80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a05d10666846f9174682115e7e9babc098764fe88c67210f24b5c842a1dcf02d12a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a4469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca2a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf92a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e91324469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca324470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba7324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf93244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b3244ef0274e31810c9df02f98fafde0f841f4e66a1cd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001adc400a9d060a9a06f90317a0b4f747b591e55db4f7b2e63a4722729b61e8dc7016c8547574cb4e53a59b586da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda00f00637435df7052c2cc9d1c3209396f67c209f517a01cd5aa20aaea405088a8a0c14fd10d3ce45960f3dcb434914e81ab369f71b79bb003e98029ec0fd65485b6a06b1eab663232f2ae50be89e40c59c90a7f33d6d30b732352464808d23479da86b901002efbae4d77a91ede0845ded7a2dddc6f3e6e4a44c5939680398793b67bc4e11bf755dd2175fbd6996b66bd7df4be5305fbcdf9dbd62abfb66ba8a07061ac6788a67f4548bfd5090e7d7d354dc4e77838eff4d8a94757ca82a75e09628831548dec8dd0ef6e067fa50f4f7fd2a1c399d8dd078adb9f5b46abd6b4fedacd080ae02ddef81676fd18db92d92c5d7c02ceadd7af0dc5f935ce5b39cc14d958c08ef1a6f094bf7bbeebcb3e0ebbf46fc627d7c2e9f59eb89fd227bba384f07cfde947ed17154a10446d5673f2a4e6951f702d33c3ee7f9ad45416153374d33639fd4f96d8e56dd7d90d0b9d955e4761136145f7becd30d4bbe7696931b5b53e6d705f028401e0a8988408583b0083f825098464f8379bb90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5830d7bffb8608c6e38ace53b5b2e6a6e05d59d6d0ba732eef4b2d1057a7c71833d863cb43fcae300f07712995911a4b0c7f45de14879064f79924549f033ddb6bc90c6909abd6740669add66f6e4a0bf673ce8f8f14a727f92d28572b88c582dc40b80b55bb1f84c8401e0a896a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb72218438401e0a897a0b4f747b591e55db4f7b2e63a4722729b61e8dc7016c8547574cb4e53a59b586d80773fcbd7bdd32ec3aaa8f479ff81d83b2645b7c88129db2bba7f0472d4f7c29d40237f191ded0754213d3a3370ab127dcced7f9d149435ed945672326523b87901a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb7221843a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ee226379db83cffc681495730c11fdde79ba4c0ca062444d3e162738b70671774b4862687181d16061c432218e4ba7a461062cbf41a05d523c486abed40b55c62490f7e6c736a650e0063ae74e276558d76a6e79f2eca04264d8ba1510e7c04bfd868e0c363667adbbdbe522fbe1aca9ca70f0a0852150b90100cfefbeff7e5ffdff3ffffffffff3fffbfff9ffff5fffffffbfafefdfffffdf7fffb5bcfdfffbd3fffffffbabf7fffe7ffffdde3ffffffff37ffedeffdffdf7fde6f7ffecfff7fdfe5fcfb7cfebf3ddffbfffffffbf5fefffffffdb7dfbffffeeeffde7e7ee5ffffefffffffaf77fdfffdfffb8fff67fefebff37efffff5ffaf37f7fffe772fff7ffdfe4ffef77f66efff7f7ffff7bf7fffdefff9bff7ffdff7fffffd7efffff7fe7efff97f5ffefceffdfdfeffdffffffbffff7ef6ffd7fefffbeffdfffbfffffcf1ffbffffb6dbfdffff9fd7ffff7fffffefbbfef7f1fff3fffbffffffd7ebdffcfffdfff2ef7bffbdffff3ffefffeeffffbfbdbfffffffeff028401e0a8978408583b008403ca4f878464f83798b90118d88301020a846765746888676f312e32302e34856c696e7578000000b19df4a2f8b5830d7bffb86092ca39301248483fdc36d490add87d766f62c450aff74d50b53a405d5c1fc0fdcc91b34c2e29438bec0d4ba5d6ed1e4d062d145f7c9190296ecc43707f1493d3f988241f660a28444b514c382e76a4930d50b82ff73653585c927e6e6a4db1e1f84c8401e0a895a07c6aabbc3fd3162a0dc3b304daab5179fa314d5aa693de4ce435a74729caaf498401e0a896a00c34e2d99d11d22eab191abb15b44c7a814759e26e3cf7d3d3fa5e6eb72218438066a0258ea8c512cf9530befba8296fe2a03ef597d255a74467b2b8cd3c77154c630589c1dbaef1a9cd54b8890e49e53c26fa4ae5e19b3de47c0bbcbfdb6f58ca01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a051097d1820f22951df90e92f90211a021f47fc4c71ce28cd9e049b3fe9dddc578f2a00ed61497c5b37bcc8e48bfcbe3a0654bd8d6f686d4d76b556e5673a3c32e86fd50778395e6ab62057d8accda70d4a0b79f5c426a78768fde22592bf8dec67dd8248ce91e5b969e5cb17544b0861ccca0d38579ccb94ccd1bca4590cf67f95eda9525c1004c742d2c1f15d050a75e1a3ea0f2ff6f14155561435bf87b9918b1d49efdbe63ef6d3859ffc6779c86d0aa6a67a03cfe521867772edf9258062588e73d070767ec119fc450c076d42eb49848e736a08233cadd954be16be47323339280fa17d8d38b7bebe66e58263864579b9160d2a0934a0a9167d33ddc0acbfd578aa6456338905da0a57818e4fed4dd6bf904242aa0117adee8e08ab69c21c3d94509780b055ce76e9fc7d246224286812c14956be0a0a325680d542e0a681f14938b6e8dba2bb67ac47c7e46c97c1e1c5016424d6938a00a52321e954fa6dc9d18364f45aca50c63626b9c11a0a59950793b427dcdc0d0a034383e09f2bc0c053ed3e951ab7e48c7118c0e5eb5b5ff0a6f57c0c9a4c06c32a0a2a0b07c45834760874054d33fc50c93d387d325d003914f0c65bf1ac27fa2caa0d4f97f9df1f99d342fb9337923449f0d897f1b2c2d6816a344851c56b1fbd925a0c553d144a0b7803722e2b6e1f008c738511ead86be5b39bbb2362fe43216e2b2a0492b5c75ec293337ac1671aac36a12fe094f9d4afc85fda5256d008a95527c7f80f90211a01482083171a85db571e8039ba0943037b2dcf62cfd7e8883ea43414f5c878989a08115d92802a81c3edbbc3b4e13bd8238de6bbd4ec41fa153a9d8150c036d84bda00ef3abd5bd4c03ca55e95d04936b5fe26435ebddd9c4c3e943be1178e95cf586a055902ca0147733add5db2b9dcb408d7438c61ff0a9c2ae6909ae0059417cf705a0a43e0b400b6e421565416a4634e04f069620c921c16c4c834d6fc5428d78a9b5a09dc094626c24d80c45be99922cb648cbc97060fab6e96e4e80993707b2c52724a0207e7aceb06a66a1700ff5608dc84284b95861ae0b807832e37293ee10cab7d2a079d0faf911472c495ff5296f3f30b7abc343f3c7554f2d0a52175c7c37aa59fea0a5a1d6a655723905c16091f689b51b617cc9d6f61d4f9ecd95c7f661d158ecd8a0469cb57e4cb8fbf50ecb243e62430f00abc984cfd2f8d3e70430df77501cc578a0d802da49895b71d47c16d9888b6d22b441ac1be36a8eb191f1f3667bd6301722a0c546ee6ab96d5fb63b782dd661c1435e9132cd55b1ae0adf12528b9e2aa17afba074ed5d006f4ac02dbbfb606de833f7f48f3f355d2b10b6fca83558404ab5c3e9a08c387e90049477e89107bbc0f23f1e74fb014a1a56d5e0ec644cfc06e0de80cca08e0739e0e80255f982390cdb4333cedc812c7d8a8b2d28f77c95d40705301864a000aaf107fb17abf295f150088edbf969395e9f865aa7c3ea494217895fff88dc80f90211a08657cad2ea1ecbfc601fe1d75015454104d868cea76db854f5f97d5d3dbe22b8a013001952cbc7164cd427beed0feedf61d8ddf54a6056fc3af40a09482fb0b904a0f96a07a3b52c4f6afa3bc94096c3dad9d716048b67b65b9372ed28b84a7f867ba0d1a7533ee10ffe325420de1cf44e66e535bf3070ee7c7bc51602bc35b0809a85a00b520f0ba3709df2263da4eeab08baa259fd89d0794a4d9ad348bbd7b0bef2a2a089ccdb49ac55b3093681b1c06f909ceab578188cd1c911685eab2ed43eb81024a0de6aec9081b3b7a30e26d71d5377b47c9822159b83d7a98e724b96a6266cf537a09b78f22559d7437452123074e41908bba67f1519573809b90e0300340ff6c526a054ea73e9e553db21ebcdde46e116030f0950babf2289788ce1cd6376e1ce1962a0c50ca2ab183d394023a58ca36d708e9af9ec51946269b377b6af60fa57b5bcc9a028e5333c4317c4807523d659248fb2588748979e3534a33e15292fb80bfe7c40a074b67a93aaba82591572a303cc67018689b97a4ce911c29e9567c2cc53903878a0c0e0b2b7f493c904f378b2697c84288cf65f19d159ef12341094eea7dab53905a05c41b85be17e61f397c7e181b8a466cd05dcb432ff5e8cfc9b6ec7fe0513e35ea043503c0c7fb469703f24cdd95a85a20386883e493e8e3381701d82c25eaed391a0a553abff5c58523d28a306247e333641c0db2b69b2678cb9cbb80628a75d746980f90211a02b0bb937e80df96357496fecc9c2867c6d6bac3f8d0ce5ab4ebed12dddc27058a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea001075113e41056754193ec2f07875210f072c2f4af49af8f2ec17dbbb0c73959a05906881965c59aec1e32a5f7f2bcfb38ddb0c6c7ab37828a904cdaac2692aedba0a126e78f29bec0484bdced0c364a0f90ea15ce796746109b99a55b41947d8433a00f300df74f29484f4ae9535e6c04f6334405ea81e5080ea5d061778623804611a07be493f4e20698e147a967a3906267dee98e7fe1415d55e6e7302ebf87eaf672a01f879933e4e640e58aec28ce41e7f2f9e489ebce2df90904113e61c4fab69c7ba0a4ce58ab185d31ab35bf68f4ab718740253d27ad14d91ccacb6cc8cd7c7383aca0202ac97dfe72828db6083d55251a2c978ed400b579e374ad36e0375ea649d252a072eda53fafe5d4470ce7a9869bfba77708f903f350e8724576ebc059142e12a7a0ba58b5b506eedfa74a4f0163a657a100916fa7d3bf298bd6f355bca173776fa3a0eab5744b05399a419026ca951cafc64b9fe509890c38daaf4681bc51a8606573a0de3920cd5b33f70046dbcc501aeb61c419d80d751aeee6179fc0a8dbc5fc8832a0a3a7e5c873ca68a89ebfd2bc67252e20a99c2d409142210173d48550b4bf9df6a092dae397f0eade2f54af3a667b7b1a26b2fa7bd84ddde17b74a25840f3fc690480f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a068586e55fe196915ff1c0372869784268e924b37a1fe030a25f5cb174eb3f5dba0ecc75a220a887f2e21476bce8fc707966851c4894e3feba4083d53bce765746da096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0194e628edfc428c2aad974e6d95aabcc65dfe92dab754b85b7c29ce15f28621aa034680d8ce0716dd6452eb4d019bfaa5b3b80d93912d6f03b22630e3c0757ddc5a0e3fb01c5b7edebe9970d16a07c52387927acbe0be058476aad7e76b1285a90b1a023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0b749fecc509a19e4ba21e91be9cc2230945e28373c35addd3319a689e063735f80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a05d10666846f9174682115e7e9babc098764fe88c67210f24b5c842a1dcf02d12a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a4469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca2a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf92a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e91324469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca324470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba7324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf93244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b3244ef0274e31810c9df02f98fafde0f841f4e66a1cd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec();
        let any: Any = any.try_into().unwrap();
        let err = client
            .submit_misbehaviour(&ctx, client_id.clone(), any)
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedSameBlockHash : 0-31500440"),
            "{}",
            err
        );

        // Invalid block
        let mut mock_consensus_state = BTreeMap::new();
        let cs = ConsensusState {
            validators_hash: hex!(
                "b54bd3446b6b08d81f85179c559c3d82a6cf4bfa6e034a061637525282c82b95"
            ),
            validators_size: 3,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 31500567), trusted_cs);
        mock_consensus_state.insert(Height::new(0, 31500400), cs.clone());
        mock_consensus_state.insert(Height::new(0, 31500200), cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: mainnet(),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };

        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212cb81010a0b78782d7061726c69612d3112dc400a9d060a9a06f90317a0ed8d44e7dd89ddc7bbd70154c37cd3707bd043bffbf9a76b0b621e986a9b0813a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942465176c461afb316ebc773c61faee85a6515daaa0589177598b87c12149cc4ad784c463ebdbeb8477f535b65db3abe23cbe23316ba0c6206c958c9879193ea4a6848f347c47a992bc325a69d7d59353f15aa956545ea09ee5cc40f087565423294d913c00e220941b26d64a06a6e76ee792225855673cb9010095a0025601c59d984806404d8512d90b730542282a10043123900102269421348402d16841041041c28e10028618c0060401e00520ca0287d8ca26300c20202063545478af34e8248d73029dc43845aa319a2cc1851220480a2631b594244504000d11226a1304035659231aa1414c08e8804c45004f40824280a4904002078199bba00d4cf531052988262a0840c47c163c27836834900af70146c0400100200a211203734b232824010bcc3aaa0513553cc14dc08841078c4020a1b00a91c8a4081442000c28c35d23a030b2225c2a22d1e6c3070c86140353444b2230abbc1f988c0332009801650106421b028fa44c60e1e0119048d05922a11018a02088028401e0a91884085832a783a4c9858464f8391bb90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5830d7bffb860b77e4fa480deff63ac73330adb4e4178bb6604424fa05f4e4b361ba0442fc6d985b9f900e7978c39f6c495020d26fd680b73f0dbc534f7c57df302bbafbb8d129d183d6034cd2c3fa55055753153f08c78161c5cbd836873ba6b8056ba6e3754f84c8401e0a916a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2d8401e0a917a0ed8d44e7dd89ddc7bbd70154c37cd3707bd043bffbf9a76b0b621e986a9b081380ebc64eda3cd045183da9308bb3652547fe7debf986ad335f6a8c6a2a430dc6d9105ae84456bce956ccf90f0d2d8f25d64464afa822e429e3d0f5facd5b4613ff00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940bac492386862ad3df4b666bc096b0505bb694daa0daecc2a1389dcd934cb7de4cab50fccb057c330e20fea5576cd6dc465c1f6c55a0e408876db85b452f96e77e2623d240f09e0ce197b988b56080032f4728300baea0a4cd4e847733c0936f37e43ce91aeee8b8c643ee1b680f3fac8b3fde197cbd3ab90100956f1e4a5702dc1dcd192d45dc98082bd5cde5643d04b6613b8fc56bd0a8f6739ab790c35a846cd372ab5488065eea72add5f20cb128e040fdb47efb82642cea647cd6446de96e56c75319bb90c07aa871df44c7efc63e4d0404ff7cc847947e7a5c8cbfeab3fe97016d82ba81319d485ac8ea10277bccb7e79dc5706ec4926afdeab3b67bfcaf0a4f9c754b5076ce8a3d7c349ded0e00cf651076c584e36961eee7023763e83a627941e3970fe78d42c0e2618a1d4383e5b76b36267725e2dcab35dfefc34388c69970ab0cd297512bb09b16e2823e71be9531d0e2caffe7eef5f9acc73d0df5c13db50762c30fa12d5cd426aff062e5ceed219ed85aa7f9fa028401e0a91784084fe2c6840374c6418464f83918b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5830d7bffb860814da4853618bb250d5acb6ee7493380e94ebe7accb92c37380046d887401b060f3c1fd41a109d93403130f192056f0d0ee1727feb07a68b381f2d813501d7f9a2b125a75f0a1a873db8c344a2bdc1a415f24b5dcb2bab5537173607f421f69df84c8401e0a915a02ee37330e30c64f1548971185a5861ab48b418f0b28d956281e1db8dc52a79ee8401e0a916a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2d809c3f336d2f104ac33ea18f35f37bf607c35fb6f649ee262b982c9a4dbbdfdd32396d92996574ba364986efba579c1cd42f0c64c123c609d56b8c318ae414317200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a051097d2820f22951df90e92f90211a07ae684482f10178c0e266ffa81305f3d07da249971de72dab1ab828828a4c840a01dc542aa10e3430ba57113bf4f5def5d0a90f0cad7ab2a2478e2e53b4e4efe95a070a8d7045d5031acf1d4fb2dca2fe81c870023388b061e155c5a81624bb6222ea09ccf9ab2948e0e275a945f119cafd10e149929bd271d2648ef0883f690c28c6da09d80d8f1c420ebdc465f2315d3400acc03028217ef6283f33a31bf2c573e99e9a06b7d919a0914d4d3b319fa3bcf3a826089a287c3f13f49af17fb27a3e8d73828a0938b24e6a3448f76b71b141bfa42a9a2568cdff6a0b006bec66ab55a2649b8cba0248573d7a0068dc3a3e77fecf1e534b9c288d9dcaa8b4feddd98b4ff9af1bff7a0959824fdb26b166f9eaaf5fb1a1739b44023a849775167301b48872e968c90f7a00e8abb0622d123f4edd1a1fa5e2b2d5714b201da9cf1f4f70c3d934a678d8ef9a0773146e822f9649759b3d785c4a10245940cc20631cdc07062f95058767dadb9a0f981b3ec293847f65c88bef5e24e64cc2d212b0ca49220c67960f416becc83a8a08aee1a679a659901d9de1a4fcd52912fc8cc286e6eb96a3423d6054dedbca42ca06e26604562d55299128aa3213696eec100dcb86fe4f44bfa9fb9a7b9588ae66da0a5def0fde805a2676a0ac3b723a0bdb1225abf30c113401d8ba8e101af3e4568a0d7bc90e94b6616131f3f56ea87c1f56168a05473c911d5cae929716626e2c8a980f90211a0e43bb49bebcd6508d64375d335f10b27581e64238beced5f20efa5c61143e4f2a0cf5f1f45f3cc1f320a273b537f8707201e8c04b70669dd9d8124d451cc0c95d2a0619077f47f96522852e6e3a52f529001b69ed3ba9455611463a7dca3a222761fa0d82254033192babbdcd30f44d182a79fec00742794281ccec99cb51d3b65df82a056af5585bac904891780415852dd3234e4371e2d19fe751d9837b00b551532d2a0e8a7997703983c25335ee205cb21bd0130928e42a643ea684f50bbe1c99cfcd7a0b2cece449d7ba9b387415d96be040995034c31872dec9930e37c3c88edd18cfaa06170a299cfc7741a72b8483eb6c9661f14580ad886b653fd703ca760d12d0c6da0f45da7c9cde88116c8c63038d61a35c1c147bbed3c9a46b84cf817802b6294cda0dd590938ea0a8917f4f42d2a74504e74156ca3f9efbcf2ebb2de7eaf03dedb47a055dbb4192fc2235ddc3f77f41cc92bf9ed3caddcc7ab44052e2f72adb9287c81a056387d805d993b79ecf7f822d818ba177eb3a35653c5d646d79b7b2b7099f0a5a08b02fffc86d76fd542272836ef3e90f5fd3a48a1c7613842e20f60736f1c251aa02d9e49d931d8b79e7b612b7640f1c0a14e8093e534059a53c93cefcd46101e70a0e958a6799e244325d08d01f77b8d19a035b5cd0c9da3e162aaf46304dd10922ea0d1665e3022f3d1f97ce1f079badf1c81d18bf870f0c4b3c140987826529a0ecf80f90211a054420a559e838e8a96dee020251c7618868f4f21a66b79bcb9820b9f51e1110ca07fc9f582ab89d52a4146493b8b643ab212a765a78b1af6eebd917b8b34b80664a03e5f697b589ecfc8221c7be03375f0e00475302856313c93849b2fdce10afc94a03fd54ff0070ad75917641f6b7036349ee4b75d94300b0a37c64a19473537a58da0f3e6dde032e9a643169def6c5be7d39c5f819d99e64a7e9a9d43fdba14244411a0fd152ece1cb82b3699f9b153528545841952d1765f12c4745bc313562ece47e3a00d8ec7a6eb2bd2cda14d5784ab0b2108e0ae36b448e4f120a7b6886099a8ed75a04fef7dd6a7deb5c00dd370fe81bff56adc6a07ce15e0e0fd9eded0e1d2484171a0552a676de74475910805bb58d3af8e7d4d10726860fcbea1f4231a6527b96620a02c89727ff5f17384684825702290b528c73b4132986f437d37a1581fafc6835ea064af69a7f803a0141f705d08e005999c4e5dfed51ec4241c65bacfde1f78240ea0b58294e9bf1374589279bb90bb0a1a72d980a1053173fff755357da6180f92b6a0cd3a419cbb2cd18b5f8c873db0926549f5b5ea8d12f700dae39d3cfe782b5d21a0a9b4ebfcdf414ed65bb5a72f8445597f80cd6a3ee339649317b62b5147672574a049c493f66dbe32969305f92199b6e8074e5a01905135b450d6f16ee552979387a0eba5d130b84ab188e414f307d79921a558aa50ab30976d06a7714e427dc3ad3f80f90211a02b0bb937e80df96357496fecc9c2867c6d6bac3f8d0ce5ab4ebed12dddc27058a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea001075113e41056754193ec2f07875210f072c2f4af49af8f2ec17dbbb0c73959a0eb17acadca248b4e5cc755a3cfbcb760d62b5b84a6f2ecfa799607bcaebaaceba0a126e78f29bec0484bdced0c364a0f90ea15ce796746109b99a55b41947d8433a0791862dd125921315b2b38f97814fe7d1c6ba6f580d2c9aed33c55361488f25ea07be493f4e20698e147a967a3906267dee98e7fe1415d55e6e7302ebf87eaf672a01f879933e4e640e58aec28ce41e7f2f9e489ebce2df90904113e61c4fab69c7ba0a4ce58ab185d31ab35bf68f4ab718740253d27ad14d91ccacb6cc8cd7c7383aca0385401466420285419fdf931b147158e190d8dc09fae48acd09a77f81d51096da072eda53fafe5d4470ce7a9869bfba77708f903f350e8724576ebc059142e12a7a05d1d65a8156c34794c7a4f12b226b135d867a7f76f39830f98cfc6c3d1672dcea08f432bfe838daa95cbff397a24c8dcbfd6c9c006f7770b3f372947a844088f89a0de3920cd5b33f70046dbcc501aeb61c419d80d751aeee6179fc0a8dbc5fc8832a017f02cd65ab60696611158d62e7a5e186512dccd9caafe3f64d73e9e1abeca24a0d8f20f38bfa4858cc3e5fe10c893c85a578ef0ef8146158d8511bf33d6700f1f80f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a068586e55fe196915ff1c0372869784268e924b37a1fe030a25f5cb174eb3f5dba0ecc75a220a887f2e21476bce8fc707966851c4894e3feba4083d53bce765746da096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0f1b54ec574ab3ea2c76c90f1241ab0d74f4c8da90749f81d9f118366105bcf0ca034680d8ce0716dd6452eb4d019bfaa5b3b80d93912d6f03b22630e3c0757ddc5a0e3fb01c5b7edebe9970d16a07c52387927acbe0be058476aad7e76b1285a90b1a023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0b749fecc509a19e4ba21e91be9cc2230945e28373c35addd3319a689e063735f80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a05d10666846f9174682115e7e9babc098764fe88c67210f24b5c842a1dcf02d12a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a4469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca2a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf92a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e91324469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca324470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba7324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf93244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b3244ef0274e31810c9df02f98fafde0f841f4e66a1cd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001adc400a9d060a9a06f90317a0ed8d44e7dd89ddc7bbd70154c37cd3707bd043bffbf9a76b0b621e986a9b0813a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942465176c461afb316ebc773c61faee85a6515daaa00000000000000000000000000000000000000000000000000000000000000000a0c6206c958c9879193ea4a6848f347c47a992bc325a69d7d59353f15aa956545ea09ee5cc40f087565423294d913c00e220941b26d64a06a6e76ee792225855673cb9010095a0025601c59d984806404d8512d90b730542282a10043123900102269421348402d16841041041c28e10028618c0060401e00520ca0287d8ca26300c20202063545478af34e8248d73029dc43845aa319a2cc1851220480a2631b594244504000d11226a1304035659231aa1414c08e8804c45004f40824280a4904002078199bba00d4cf531052988262a0840c47c163c27836834900af70146c0400100200a211203734b232824010bcc3aaa0513553cc14dc08841078c4020a1b00a91c8a4081442000c28c35d23a030b2225c2a22d1e6c3070c86140353444b2230abbc1f988c0332009801650106421b028fa44c60e1e0119048d05922a11018a02088028401e0a91884085832a783a4c9858464f8391bb90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5830d7bffb860b77e4fa480deff63ac73330adb4e4178bb6604424fa05f4e4b361ba0442fc6d985b9f900e7978c39f6c495020d26fd680b73f0dbc534f7c57df302bbafbb8d129d183d6034cd2c3fa55055753153f08c78161c5cbd836873ba6b8056ba6e3754f84c8401e0a916a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2d8401e0a917a0ed8d44e7dd89ddc7bbd70154c37cd3707bd043bffbf9a76b0b621e986a9b081380ebc64eda3cd045183da9308bb3652547fe7debf986ad335f6a8c6a2a430dc6d9105ae84456bce956ccf90f0d2d8f25d64464afa822e429e3d0f5facd5b4613ff00a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080129e060a9b06f90318a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940bac492386862ad3df4b666bc096b0505bb694daa0daecc2a1389dcd934cb7de4cab50fccb057c330e20fea5576cd6dc465c1f6c55a0e408876db85b452f96e77e2623d240f09e0ce197b988b56080032f4728300baea0a4cd4e847733c0936f37e43ce91aeee8b8c643ee1b680f3fac8b3fde197cbd3ab90100956f1e4a5702dc1dcd192d45dc98082bd5cde5643d04b6613b8fc56bd0a8f6739ab790c35a846cd372ab5488065eea72add5f20cb128e040fdb47efb82642cea647cd6446de96e56c75319bb90c07aa871df44c7efc63e4d0404ff7cc847947e7a5c8cbfeab3fe97016d82ba81319d485ac8ea10277bccb7e79dc5706ec4926afdeab3b67bfcaf0a4f9c754b5076ce8a3d7c349ded0e00cf651076c584e36961eee7023763e83a627941e3970fe78d42c0e2618a1d4383e5b76b36267725e2dcab35dfefc34388c69970ab0cd297512bb09b16e2823e71be9531d0e2caffe7eef5f9acc73d0df5c13db50762c30fa12d5cd426aff062e5ceed219ed85aa7f9fa028401e0a91784084fe2c6840374c6418464f83918b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5830d7bffb860814da4853618bb250d5acb6ee7493380e94ebe7accb92c37380046d887401b060f3c1fd41a109d93403130f192056f0d0ee1727feb07a68b381f2d813501d7f9a2b125a75f0a1a873db8c344a2bdc1a415f24b5dcb2bab5537173607f421f69df84c8401e0a915a02ee37330e30c64f1548971185a5861ab48b418f0b28d956281e1db8dc52a79ee8401e0a916a04006073a211a39b6f113685a46c6771dc02c5a2e5491d30544847c7e0e492c2d809c3f336d2f104ac33ea18f35f37bf607c35fb6f649ee262b982c9a4dbbdfdd32396d92996574ba364986efba579c1cd42f0c64c123c609d56b8c318ae414317200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801a051097d2820f22951df90e92f90211a07ae684482f10178c0e266ffa81305f3d07da249971de72dab1ab828828a4c840a01dc542aa10e3430ba57113bf4f5def5d0a90f0cad7ab2a2478e2e53b4e4efe95a070a8d7045d5031acf1d4fb2dca2fe81c870023388b061e155c5a81624bb6222ea09ccf9ab2948e0e275a945f119cafd10e149929bd271d2648ef0883f690c28c6da09d80d8f1c420ebdc465f2315d3400acc03028217ef6283f33a31bf2c573e99e9a06b7d919a0914d4d3b319fa3bcf3a826089a287c3f13f49af17fb27a3e8d73828a0938b24e6a3448f76b71b141bfa42a9a2568cdff6a0b006bec66ab55a2649b8cba0248573d7a0068dc3a3e77fecf1e534b9c288d9dcaa8b4feddd98b4ff9af1bff7a0959824fdb26b166f9eaaf5fb1a1739b44023a849775167301b48872e968c90f7a00e8abb0622d123f4edd1a1fa5e2b2d5714b201da9cf1f4f70c3d934a678d8ef9a0773146e822f9649759b3d785c4a10245940cc20631cdc07062f95058767dadb9a0f981b3ec293847f65c88bef5e24e64cc2d212b0ca49220c67960f416becc83a8a08aee1a679a659901d9de1a4fcd52912fc8cc286e6eb96a3423d6054dedbca42ca06e26604562d55299128aa3213696eec100dcb86fe4f44bfa9fb9a7b9588ae66da0a5def0fde805a2676a0ac3b723a0bdb1225abf30c113401d8ba8e101af3e4568a0d7bc90e94b6616131f3f56ea87c1f56168a05473c911d5cae929716626e2c8a980f90211a0e43bb49bebcd6508d64375d335f10b27581e64238beced5f20efa5c61143e4f2a0cf5f1f45f3cc1f320a273b537f8707201e8c04b70669dd9d8124d451cc0c95d2a0619077f47f96522852e6e3a52f529001b69ed3ba9455611463a7dca3a222761fa0d82254033192babbdcd30f44d182a79fec00742794281ccec99cb51d3b65df82a056af5585bac904891780415852dd3234e4371e2d19fe751d9837b00b551532d2a0e8a7997703983c25335ee205cb21bd0130928e42a643ea684f50bbe1c99cfcd7a0b2cece449d7ba9b387415d96be040995034c31872dec9930e37c3c88edd18cfaa06170a299cfc7741a72b8483eb6c9661f14580ad886b653fd703ca760d12d0c6da0f45da7c9cde88116c8c63038d61a35c1c147bbed3c9a46b84cf817802b6294cda0dd590938ea0a8917f4f42d2a74504e74156ca3f9efbcf2ebb2de7eaf03dedb47a055dbb4192fc2235ddc3f77f41cc92bf9ed3caddcc7ab44052e2f72adb9287c81a056387d805d993b79ecf7f822d818ba177eb3a35653c5d646d79b7b2b7099f0a5a08b02fffc86d76fd542272836ef3e90f5fd3a48a1c7613842e20f60736f1c251aa02d9e49d931d8b79e7b612b7640f1c0a14e8093e534059a53c93cefcd46101e70a0e958a6799e244325d08d01f77b8d19a035b5cd0c9da3e162aaf46304dd10922ea0d1665e3022f3d1f97ce1f079badf1c81d18bf870f0c4b3c140987826529a0ecf80f90211a054420a559e838e8a96dee020251c7618868f4f21a66b79bcb9820b9f51e1110ca07fc9f582ab89d52a4146493b8b643ab212a765a78b1af6eebd917b8b34b80664a03e5f697b589ecfc8221c7be03375f0e00475302856313c93849b2fdce10afc94a03fd54ff0070ad75917641f6b7036349ee4b75d94300b0a37c64a19473537a58da0f3e6dde032e9a643169def6c5be7d39c5f819d99e64a7e9a9d43fdba14244411a0fd152ece1cb82b3699f9b153528545841952d1765f12c4745bc313562ece47e3a00d8ec7a6eb2bd2cda14d5784ab0b2108e0ae36b448e4f120a7b6886099a8ed75a04fef7dd6a7deb5c00dd370fe81bff56adc6a07ce15e0e0fd9eded0e1d2484171a0552a676de74475910805bb58d3af8e7d4d10726860fcbea1f4231a6527b96620a02c89727ff5f17384684825702290b528c73b4132986f437d37a1581fafc6835ea064af69a7f803a0141f705d08e005999c4e5dfed51ec4241c65bacfde1f78240ea0b58294e9bf1374589279bb90bb0a1a72d980a1053173fff755357da6180f92b6a0cd3a419cbb2cd18b5f8c873db0926549f5b5ea8d12f700dae39d3cfe782b5d21a0a9b4ebfcdf414ed65bb5a72f8445597f80cd6a3ee339649317b62b5147672574a049c493f66dbe32969305f92199b6e8074e5a01905135b450d6f16ee552979387a0eba5d130b84ab188e414f307d79921a558aa50ab30976d06a7714e427dc3ad3f80f90211a02b0bb937e80df96357496fecc9c2867c6d6bac3f8d0ce5ab4ebed12dddc27058a0a6cef11baa7cdf85210135c2bc68973f8e949f861a7397bddddf55147f94e2dea001075113e41056754193ec2f07875210f072c2f4af49af8f2ec17dbbb0c73959a0eb17acadca248b4e5cc755a3cfbcb760d62b5b84a6f2ecfa799607bcaebaaceba0a126e78f29bec0484bdced0c364a0f90ea15ce796746109b99a55b41947d8433a0791862dd125921315b2b38f97814fe7d1c6ba6f580d2c9aed33c55361488f25ea07be493f4e20698e147a967a3906267dee98e7fe1415d55e6e7302ebf87eaf672a01f879933e4e640e58aec28ce41e7f2f9e489ebce2df90904113e61c4fab69c7ba0a4ce58ab185d31ab35bf68f4ab718740253d27ad14d91ccacb6cc8cd7c7383aca0385401466420285419fdf931b147158e190d8dc09fae48acd09a77f81d51096da072eda53fafe5d4470ce7a9869bfba77708f903f350e8724576ebc059142e12a7a05d1d65a8156c34794c7a4f12b226b135d867a7f76f39830f98cfc6c3d1672dcea08f432bfe838daa95cbff397a24c8dcbfd6c9c006f7770b3f372947a844088f89a0de3920cd5b33f70046dbcc501aeb61c419d80d751aeee6179fc0a8dbc5fc8832a017f02cd65ab60696611158d62e7a5e186512dccd9caafe3f64d73e9e1abeca24a0d8f20f38bfa4858cc3e5fe10c893c85a578ef0ef8146158d8511bf33d6700f1f80f90211a09266cc171961bdbe99b5d3e81222891584360854ab3bd0ba637b0328045638cfa0701a701e14ff5249c51efc72d994fdb08774307c79c6de9cc6fa40d0ef822be2a068586e55fe196915ff1c0372869784268e924b37a1fe030a25f5cb174eb3f5dba0ecc75a220a887f2e21476bce8fc707966851c4894e3feba4083d53bce765746da096ac70b809e1cc20c66b9777dbf64d6ab9761c8fbb8a9bc7ceb7b13ddc5700bda0d34c641dc1ef3491414764589b9ba400d1031fd5762401769b75381284b27aa9a02c8e199513447acad095bc3055d8ddde105b40e08816f48ab794f85dd6b8247fa0a908de3ec739b00b9d10c8dc00f628e890970f9aa9aef9a86cf9a1f6b22ff6f1a0f1b54ec574ab3ea2c76c90f1241ab0d74f4c8da90749f81d9f118366105bcf0ca034680d8ce0716dd6452eb4d019bfaa5b3b80d93912d6f03b22630e3c0757ddc5a0e3fb01c5b7edebe9970d16a07c52387927acbe0be058476aad7e76b1285a90b1a023649d744d41560614e1662a93059ad7cdd8e797dc02fecb0afef8d2f3433438a042f19b7930e9573b999b08fb6c0a1d5202463411a71260ab35111c0e4abaf214a049336eef38e9dc1a5e17a2355ab660d77597f3c28aece83dcaea1ebec84843c0a0dd5172ff0b4d923550639808205f38c327122ae295d3665d38bfa18c8353b926a0b749fecc509a19e4ba21e91be9cc2230945e28373c35addd3319a689e063735f80f90211a06505ca81e32b2f5fc16bb0e57d08b63cf94273063579ce1dba42c410fcb5241ea0c6c70650f6edd7057de9a8d7aeb5a52bc40dffb8a9cb71d55990a628f1596402a03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0f9e0c0fad1c45acb28e2c52c22d8a34b91b0033d758ba237e7cce78321555219a05d10666846f9174682115e7e9babc098764fe88c67210f24b5c842a1dcf02d12a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a0fa59d52ce31992709b7380abb4db6a33327763297b3c94791f348d886c7125faa08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a0e8ff4ce1d72375673ffacb49b9c6508ab72e13b22a2017b437d74381b977fd60a027260ee4cb30c6d9777f583271ce726c44b7a0d94a066a365833a101439c7f43a0c7035c196627d2e6754f2a2ee7f93b829aa13ed595898aa4c4e8fb5454ef9693a0ac0b668136cd535099f69475c16ca2bae9e920e6513c30d2d563d3db0991659da0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a0ce5c5a5d4657257f3e6a3abc403ef40e586bfb7319420b3dedf6c03c8396a60380f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a02d17e5d80adfe7bb5ee6ad2c69f508f60d60182e0b724de4bcbfb0e6487bb378808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a44295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912a4469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca2a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf92a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e32442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8163244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e91324469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca324470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba7324472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5132447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e32448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694853244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7413244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de73244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244b8f7166496996a7da21cf1f1b04d9b3e26a3d0778974616fe8ab950a3cded19b1d16ff49c97bf5af65154b3b097d5523eb213f3d35fc5c57e7276c7f2d83be87ebfdcdf93244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd3244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4193244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7393244d93dbfb27e027f5e9e6da52b9e1c413ce35adc110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d213244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921833244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b3244ef0274e31810c9df02f98fafde0f841f4e66a1cd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec();
        let any: Any = any.try_into().unwrap();
        let err = client
            .submit_misbehaviour(&ctx, client_id, any)
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedCoinbase: 31500568"),
            "{}",
            err
        );
    }
}
