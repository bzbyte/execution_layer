//! This crate provides an abstraction over one or more *execution engines*. An execution engine
//! was formerly known as an "eth1 node", like Geth, Nethermind, Erigon, etc.
//!
//! This crate only provides useful functionality for "The Merge", it does not provide any of the
//! deposit-contract functionality that the `beacon_node/eth1` crate already provides.

use crate::payload_cache::PayloadCache;
use auth::{strip_prefix, Auth, JwtKey};
pub use engine_api::EngineCapabilities;
use engine_api::Error as ApiError;
pub use types;
pub use engine_api::*;
pub use engine_api::{http, http::deposit_methods, http::HttpJsonRpc};
use engines::{Engine, EngineError};
pub use engines::{EngineState, ForkchoiceState};
use lru::LruCache;
use payload_status::process_payload_status;
pub use payload_status::PayloadStatus;
pub use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, warn, Logger};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strum::AsRefStr;
use task_executor::TaskExecutor;
use tokio::{
    sync::{Mutex, MutexGuard, RwLock},
    time::sleep,
};
use tokio_stream::wrappers::WatchStream;

use types::{AbstractExecPayload, BeaconStateError, Blob, Checkpoint, KzgCommitment};
use types::{
    BlindedPayload, BlockType, ChainSpec, Epoch, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadCapella, ExecutionPayloadEip4844, ExecutionPayloadMerge, ForkName,
    ProposerPreparationData, PublicKeyBytes, Signature, Slot, Uint256,
};

mod block_hash;
pub mod engine_api;
pub mod engines;
mod keccak;
mod metrics;
pub mod payload_cache;
mod payload_status;
pub mod test_utils;

/// Parameters which are cached between calls to `Self::get_head`.
#[derive(Clone, Copy)]
pub struct ForkchoiceUpdateParameters {
    pub head_root: Hash256,
    pub head_hash: Option<ExecutionBlockHash>,
    pub justified_hash: Option<ExecutionBlockHash>,
    pub finalized_hash: Option<ExecutionBlockHash>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ForkChoiceView {
    pub head_block_root: Hash256,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}

/// Indicates the default jwt authenticated execution endpoint.
pub const DEFAULT_EXECUTION_ENDPOINT: &str = "http://localhost:8551/";

/// Name for the default file used for the jwt secret.
pub const DEFAULT_JWT_FILE: &str = "jwt.hex";

/// Each time the `ExecutionLayer` retrieves a block from an execution node, it stores that block
/// in an LRU cache to avoid redundant lookups. This is the size of that cache.
const EXECUTION_BLOCKS_LRU_CACHE_SIZE: usize = 128;

/// A fee recipient address for use during block production. Only used as a very last resort if
/// there is no address provided by the user.
///
/// ## Note
///
/// This is *not* the zero-address, since Geth has been known to return errors for a coinbase of
/// 0x00..00.
const DEFAULT_SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// A payload alongside some information about where it came from.
enum ProvenancedPayload<P> {
    /// A good ol' fashioned farm-to-table payload from your local EE.
    Local(P),
    /// A payload from a builder (e.g. mev-boost).
    _Builder(P),
}

#[derive(Debug)]
pub enum Error {
    NoEngine,
    NoPayloadBuilder,
    ApiError(ApiError),
    NoHeaderFromBuilder,
    CannotProduceHeader,
    EngineError(Box<EngineError>),
    NotSynced,
    ShuttingDown,
    FeeRecipientUnspecified,
    MissingLatestValidHash,
    BlockHashMismatch {
        computed: ExecutionBlockHash,
        payload: ExecutionBlockHash,
        transactions_root: Hash256,
    },
    InvalidJWTSecret(String),
    BeaconStateError(BeaconStateError),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

pub enum BlockProposalContents<T: EthSpec, Payload: AbstractExecPayload<T>> {
    Payload {
        payload: Payload,
        block_value: Uint256,
    },
    PayloadAndBlobs {
        payload: Payload,
        block_value: Uint256,
        kzg_commitments: Vec<KzgCommitment>,
        blobs: Vec<Blob<T>>,
    },
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> BlockProposalContents<T, Payload> {
    pub fn payload(&self) -> &Payload {
        match self {
            Self::Payload {
                payload,
                block_value: _,
            } => payload,
            Self::PayloadAndBlobs {
                payload,
                block_value: _,
                kzg_commitments: _,
                blobs: _,
            } => payload,
        }
    }
    pub fn to_payload(self) -> Payload {
        match self {
            Self::Payload {
                payload,
                block_value: _,
            } => payload,
            Self::PayloadAndBlobs {
                payload,
                block_value: _,
                kzg_commitments: _,
                blobs: _,
            } => payload,
        }
    }
    pub fn kzg_commitments(&self) -> Option<&[KzgCommitment]> {
        match self {
            Self::Payload {
                payload: _,
                block_value: _,
            } => None,
            Self::PayloadAndBlobs {
                payload: _,
                block_value: _,
                kzg_commitments,
                blobs: _,
            } => Some(kzg_commitments),
        }
    }
    pub fn blobs(&self) -> Option<&[Blob<T>]> {
        match self {
            Self::Payload {
                payload: _,
                block_value: _,
            } => None,
            Self::PayloadAndBlobs {
                payload: _,
                block_value: _,
                kzg_commitments: _,
                blobs,
            } => Some(blobs),
        }
    }
    pub fn block_value(&self) -> &Uint256 {
        match self {
            Self::Payload {
                payload: _,
                block_value,
            } => block_value,
            Self::PayloadAndBlobs {
                payload: _,
                block_value,
                kzg_commitments: _,
                blobs: _,
            } => block_value,
        }
    }
    pub fn default_at_fork(fork_name: ForkName) -> Result<Self, BeaconStateError> {
        Ok(match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                BlockProposalContents::Payload {
                    payload: Payload::default_at_fork(fork_name)?,
                    block_value: Uint256::zero(),
                }
            }
            ForkName::Eip4844 => BlockProposalContents::PayloadAndBlobs {
                payload: Payload::default_at_fork(fork_name)?,
                block_value: Uint256::zero(),
                blobs: vec![],
                kzg_commitments: vec![],
            },
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct ProposerPreparationDataEntry {
    update_epoch: Epoch,
    preparation_data: ProposerPreparationData,
}

#[derive(Hash, PartialEq, Eq)]
pub struct ProposerKey {
    slot: Slot,
    head_block_root: Hash256,
}

#[derive(PartialEq, Clone)]
pub struct Proposer {
    validator_index: u64,
    payload_attributes: PayloadAttributes,
}

/// Information from the beacon chain that is necessary for querying the builder API.
pub struct BuilderParams {
    pub pubkey: PublicKeyBytes,
    pub slot: Slot,
    pub chain_health: ChainHealth,
}

pub enum ChainHealth {
    Healthy,
    Unhealthy(FailedCondition),
    Optimistic,
    PreMerge,
}

#[derive(Debug)]
pub enum FailedCondition {
    Skips,
    SkipsPerEpoch,
    EpochsSinceFinalization,
}

struct Inner<E: EthSpec> {
    engine: Arc<Engine>,
    execution_engine_forkchoice_lock: Mutex<()>,
    suggested_fee_recipient: Option<Address>,
    proposer_preparation_data: Mutex<HashMap<u64, ProposerPreparationDataEntry>>,
    execution_blocks: Mutex<LruCache<ExecutionBlockHash, ExecutionBlock>>,
    proposers: RwLock<HashMap<ProposerKey, Proposer>>,
    executor: TaskExecutor,
    payload_cache: PayloadCache<E>,
    _builder_profit_threshold: Uint256,
    log: Logger,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint urls for EL nodes that are running the engine api.
    pub execution_endpoints: Vec<SensitiveUrl>,
    /// Endpoint urls for services providing the builder api.
    pub builder_url: Option<SensitiveUrl>,
    /// JWT secrets for the above endpoints running the engine api.
    pub secret_files: Vec<PathBuf>,
    /// The default fee recipient to use on the beacon node if none if provided from
    /// the validator client during block preparation.
    pub suggested_fee_recipient: Option<Address>,
    /// An optional id for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_id: Option<String>,
    /// An optional client version for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_version: Option<String>,
    /// Default directory for the jwt secret if not provided through cli.
    pub default_datadir: PathBuf,
    /// The minimum value of an external payload for it to be considered in a proposal.
    pub builder_profit_threshold: u128,
    pub execution_timeout_multiplier: Option<u32>,
}

/// Provides access to one execution engine and provides a neat interface for consumption by the
/// `BeaconChain`.
#[derive(Clone)]
pub struct ExecutionLayer<T: EthSpec> {
    inner: Arc<Inner<T>>,
}

impl<T: EthSpec> ExecutionLayer<T> {
    /// Instantiate `Self` with an Execution engine specified in `Config`, using JSON-RPC via HTTP.
    pub fn from_config(config: Config, executor: TaskExecutor, log: Logger) -> Result<Self, Error> {
        let Config {
            execution_endpoints: urls,
            builder_url: _,
            secret_files,
            suggested_fee_recipient,
            jwt_id,
            jwt_version,
            default_datadir,
            builder_profit_threshold,
            execution_timeout_multiplier,
        } = config;

        if urls.len() > 1 {
            warn!(log, "Only the first execution engine url will be used");
        }
        let execution_url = urls.into_iter().next().ok_or(Error::NoEngine)?;

        // Use the default jwt secret path if not provided via cli.
        let secret_file = secret_files
            .into_iter()
            .next()
            .unwrap_or_else(|| default_datadir.join(DEFAULT_JWT_FILE));

        let jwt_key = if secret_file.exists() {
            // Read secret from file if it already exists
            std::fs::read_to_string(&secret_file)
                .map_err(|e| format!("Failed to read JWT secret file. Error: {:?}", e))
                .and_then(|ref s| {
                    let secret = JwtKey::from_slice(
                        &hex::decode(strip_prefix(s.trim_end()))
                            .map_err(|e| format!("Invalid hex string: {:?}", e))?,
                    )?;
                    Ok(secret)
                })
                .map_err(Error::InvalidJWTSecret)
        } else {
            // Create a new file and write a randomly generated secret to it if file does not exist
            std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(&secret_file)
                .map_err(|e| format!("Failed to open JWT secret file. Error: {:?}", e))
                .and_then(|mut f| {
                    let secret = auth::JwtKey::random();
                    f.write_all(secret.hex_string().as_bytes())
                        .map_err(|e| format!("Failed to write to JWT secret file: {:?}", e))?;
                    Ok(secret)
                })
                .map_err(Error::InvalidJWTSecret)
        }?;

        let engine: Engine = {
            let auth = Auth::new(jwt_key, jwt_id, jwt_version);
            debug!(log, "Loaded execution endpoint"; "endpoint" => %execution_url, "jwt_path" => ?secret_file.as_path());
            let api = HttpJsonRpc::new_with_auth(execution_url, auth, execution_timeout_multiplier)
                .map_err(Error::ApiError)?;
            Engine::new(api, executor.clone(), &log)
        };

        let inner = Inner {
            engine: Arc::new(engine),
            execution_engine_forkchoice_lock: <_>::default(),
            suggested_fee_recipient,
            proposer_preparation_data: Mutex::new(HashMap::new()),
            proposers: RwLock::new(HashMap::new()),
            execution_blocks: Mutex::new(LruCache::new(EXECUTION_BLOCKS_LRU_CACHE_SIZE)),
            executor,
            payload_cache: PayloadCache::default(),
            _builder_profit_threshold: Uint256::from(builder_profit_threshold),
            log,
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[allow(dead_code)]
impl<T: EthSpec> ExecutionLayer<T> {
    fn engine(&self) -> &Arc<Engine> {
        &self.inner.engine
    }

    /// Cache a full payload, keyed on the `tree_hash_root` of the payload
    fn cache_payload(&self, payload: ExecutionPayloadRef<T>) -> Option<ExecutionPayload<T>> {
        self.inner.payload_cache.put(payload.clone_from_ref())
    }

    /// Attempt to retrieve a full payload from the payload cache by the payload root
    pub fn get_payload_by_root(&self, root: &Hash256) -> Option<ExecutionPayload<T>> {
        self.inner.payload_cache.pop(root)
    }

    pub fn executor(&self) -> &TaskExecutor {
        &self.inner.executor
    }

    /// Get the current difficulty of the PoW chain.
    pub async fn get_current_difficulty(&self) -> Result<Uint256, ApiError> {
        let block = self
            .engine()
            .api
            .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
            .await?
            .ok_or(ApiError::ExecutionHeadBlockNotFound)?;
        Ok(block.total_difficulty)
    }
    /// Note: this function returns a mutex guard, be careful to avoid deadlocks.
    async fn execution_blocks(
        &self,
    ) -> MutexGuard<'_, LruCache<ExecutionBlockHash, ExecutionBlock>> {
        self.inner.execution_blocks.lock().await
    }

    /// Gives access to a channel containing if the last engine state is online or not.
    ///
    /// This can be called several times.
    pub async fn get_responsiveness_watch(&self) -> WatchStream<EngineState> {
        self.engine().watch_state().await
    }

    /// Note: this function returns a mutex guard, be careful to avoid deadlocks.
    async fn proposer_preparation_data(
        &self,
    ) -> MutexGuard<'_, HashMap<u64, ProposerPreparationDataEntry>> {
        self.inner.proposer_preparation_data.lock().await
    }

    fn proposers(&self) -> &RwLock<HashMap<ProposerKey, Proposer>> {
        &self.inner.proposers
    }

    fn log(&self) -> &Logger {
        &self.inner.log
    }

    pub async fn execution_engine_forkchoice_lock(&self) -> MutexGuard<'_, ()> {
        self.inner.execution_engine_forkchoice_lock.lock().await
    }

    /// Convenience function to allow spawning a task without waiting for the result.
    pub fn spawn<F, U>(&self, generate_future: F, name: &'static str)
    where
        F: FnOnce(Self) -> U,
        U: Future<Output = ()> + Send + 'static,
    {
        self.executor().spawn(generate_future(self.clone()), name);
    }

    /// Spawns a routine which cleans the cached proposer data periodically.

    /// Spawns a routine that polls the `exchange_transition_configuration` endpoint.
    pub fn spawn_transition_configuration_poll(&self, spec: ChainSpec) {
        let routine = |el: ExecutionLayer<T>| async move {
            loop {
                if let Err(e) = el.exchange_transition_configuration(&spec).await {
                    error!(
                        el.log(),
                        "Failed to check transition config";
                        "error" => ?e
                    );
                }
                sleep(CONFIG_POLL_INTERVAL).await;
            }
        };

        self.spawn(routine, "exec_config_poll");
    }

    /// Returns `true` if the execution engine is synced and reachable.
    pub async fn is_synced(&self) -> bool {
        self.engine().is_synced().await
    }

    /// Execution nodes return a "SYNCED" response when they do not have any peers.
    ///
    /// This function is a wrapper over `Self::is_synced` that makes an additional
    /// check for the execution layer sync status. Checks if the latest block has
    /// a `block_number != 0`.
    /// Returns the `Self::is_synced` response if unable to get latest block.
    pub async fn is_synced_for_notifier(&self) -> bool {
        let synced = self.is_synced().await;
        if synced {
            if let Ok(Some(block)) = self
                .engine()
                .api
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
            {
                if block.block_number == 0 {
                    return false;
                }
            }
        }
        synced
    }

    /// Updates the proposer preparation data provided by validators
    pub async fn update_proposer_preparation(
        &self,
        update_epoch: Epoch,
        preparation_data: &[ProposerPreparationData],
    ) {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;
        for preparation_entry in preparation_data {
            let new = ProposerPreparationDataEntry {
                update_epoch,
                preparation_data: preparation_entry.clone(),
            };

            let existing =
                proposer_preparation_data.insert(preparation_entry.validator_index, new.clone());

            if existing != Some(new) {
                metrics::inc_counter(&metrics::EXECUTION_LAYER_PROPOSER_DATA_UPDATED);
            }
        }
    }

    /// Removes expired entries from proposer_preparation_data and proposers caches
    async fn clean_proposer_caches(&self, current_epoch: Epoch) -> Result<(), Error> {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;

        // Keep all entries that have been updated in the last 2 epochs
        let retain_epoch = current_epoch.saturating_sub(Epoch::new(2));
        proposer_preparation_data.retain(|_validator_index, preparation_entry| {
            preparation_entry.update_epoch >= retain_epoch
        });
        drop(proposer_preparation_data);

        let retain_slot = retain_epoch.start_slot(T::slots_per_epoch());
        self.proposers()
            .write()
            .await
            .retain(|proposer_key, _proposer| proposer_key.slot >= retain_slot);

        Ok(())
    }

    /// Returns `true` if there have been any validators registered via
    /// `Self::update_proposer_preparation`.
    pub async fn has_any_proposer_preparation_data(&self) -> bool {
        !self.proposer_preparation_data().await.is_empty()
    }

    /// Returns `true` if the `proposer_index` has registered as a local validator via
    /// `Self::update_proposer_preparation`.
    pub async fn has_proposer_preparation_data(&self, proposer_index: u64) -> bool {
        self.proposer_preparation_data()
            .await
            .contains_key(&proposer_index)
    }

    /// Check if a proposer is registered as a local validator, *from a synchronous context*.
    ///
    /// This method MUST NOT be called from an async task.
    pub fn has_proposer_preparation_data_blocking(&self, proposer_index: u64) -> bool {
        self.inner
            .proposer_preparation_data
            .blocking_lock()
            .contains_key(&proposer_index)
    }

    /// Returns the fee-recipient address that should be used to build a block
    pub async fn get_suggested_fee_recipient(&self, proposer_index: u64) -> Address {
        if let Some(preparation_data_entry) =
            self.proposer_preparation_data().await.get(&proposer_index)
        {
            // The values provided via the API have first priority.
            preparation_data_entry.preparation_data.fee_recipient
        } else if let Some(address) = self.inner.suggested_fee_recipient {
            // If there has been no fee recipient provided via the API, but the BN has been provided
            // with a global default address, use that.
            address
        } else {
            // If there is no user-provided fee recipient, use a junk value and complain loudly.
            crit!(
                self.log(),
                "Fee recipient unknown";
                "msg" => "the suggested_fee_recipient was unknown during block production. \
                a junk address was used, rewards were lost! \
                check the --suggested-fee-recipient flag and VC configuration.",
                "proposer_index" => ?proposer_index
            );

            Address::from_slice(&DEFAULT_SUGGESTED_FEE_RECIPIENT)
        }
    }

    /// Maps to the `engine_getPayload` JSON-RPC call.
    ///
    /// However, it will attempt to call `self.prepare_payload` if it cannot find an existing
    /// payload id for the given parameters.
    ///
    /// ## Fallback Behavior
    ///
    /// The result will be returned from the first node that returns successfully. No more nodes
    /// will be contacted.
    pub async fn get_payload<Payload: AbstractExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        _builder_params: BuilderParams,
        current_fork: ForkName,
        _spec: &ChainSpec,
    ) -> Result<BlockProposalContents<T, Payload>, Error> {
        let payload_result = match Payload::block_type() {
            BlockType::Blinded => Err(Error::CannotProduceHeader),
            BlockType::Full => {
                let _timer = metrics::start_timer_vec(
                    &metrics::EXECUTION_LAYER_REQUEST_TIMES,
                    &[metrics::GET_PAYLOAD],
                );
                self.get_full_payload(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    current_fork,
                )
                .await
                .map(ProvenancedPayload::Local)
            }
        };

        // Track some metrics and return the result.
        match payload_result {
            Ok(ProvenancedPayload::Local(block_proposal_contents)) => {
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                    &[metrics::SUCCESS],
                );
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_SOURCE,
                    &[metrics::LOCAL],
                );
                Ok(block_proposal_contents)
            }
            Ok(ProvenancedPayload::_Builder(block_proposal_contents)) => {
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                    &[metrics::SUCCESS],
                );
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_SOURCE,
                    &[metrics::BUILDER],
                );
                Ok(block_proposal_contents)
            }
            Err(e) => {
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                    &[metrics::FAILURE],
                );
                Err(e)
            }
        }
    }

    /// Get a full payload without caching its result in the execution layer's payload cache.
    async fn get_full_payload<Payload: AbstractExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
    ) -> Result<BlockProposalContents<T, Payload>, Error> {
        self.get_full_payload_with(
            parent_hash,
            payload_attributes,
            forkchoice_update_params,
            current_fork,
            noop,
        )
        .await
    }

    /// Get a full payload and cache its result in the execution layer's payload cache.
    async fn get_full_payload_caching<Payload: AbstractExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
    ) -> Result<BlockProposalContents<T, Payload>, Error> {
        self.get_full_payload_with(
            parent_hash,
            payload_attributes,
            forkchoice_update_params,
            current_fork,
            Self::cache_payload,
        )
        .await
    }

    async fn get_full_payload_with<Payload: AbstractExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
        f: fn(&ExecutionLayer<T>, ExecutionPayloadRef<T>) -> Option<ExecutionPayload<T>>,
    ) -> Result<BlockProposalContents<T, Payload>, Error> {
        self.engine()
            .request(move |engine| async move {
                let payload_id = if let Some(id) = engine
                    .get_payload_id(&parent_hash, payload_attributes)
                    .await
                {
                    // The payload id has been cached for this engine.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::HIT],
                    );
                    id
                } else {
                    // The payload id has *not* been cached. Trigger an artificial
                    // fork choice update to retrieve a payload ID.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::MISS],
                    );
                    let fork_choice_state = ForkchoiceState {
                        head_block_hash: parent_hash,
                        safe_block_hash: forkchoice_update_params
                            .justified_hash
                            .unwrap_or_else(ExecutionBlockHash::zero),
                        finalized_block_hash: forkchoice_update_params
                            .finalized_hash
                            .unwrap_or_else(ExecutionBlockHash::zero),
                    };

                    let response = engine
                        .notify_forkchoice_updated(
                            fork_choice_state,
                            Some(payload_attributes.clone()),
                            self.log(),
                        )
                        .await?;

                    match response.payload_id {
                        Some(payload_id) => payload_id,
                        None => {
                            error!(
                                self.log(),
                                "Exec engine unable to produce payload";
                                "msg" => "No payload ID, the engine is likely syncing. \
                                          This has the potential to cause a missed block proposal.",
                                "status" => ?response.payload_status
                            );
                            return Err(ApiError::PayloadIdUnavailable);
                        }
                    }
                };

                let blob_fut = async {
                    match current_fork {
                        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                            None
                        }
                        ForkName::Eip4844 => {
                            debug!(
                                self.log(),
                                "Issuing engine_getBlobsBundle";
                                "suggested_fee_recipient" => ?payload_attributes.suggested_fee_recipient(),
                                "prev_randao" => ?payload_attributes.prev_randao(),
                                "timestamp" => payload_attributes.timestamp(),
                                "parent_hash" => ?parent_hash,
                            );
                            Some(engine.api.get_blobs_bundle_v1::<T>(payload_id).await)
                        }
                    }
                };
                let payload_fut = async {
                    debug!(
                        self.log(),
                        "Issuing engine_getPayload";
                        "suggested_fee_recipient" => ?payload_attributes.suggested_fee_recipient(),
                        "prev_randao" => ?payload_attributes.prev_randao(),
                        "timestamp" => payload_attributes.timestamp(),
                        "parent_hash" => ?parent_hash,
                    );
                    engine.api.get_payload::<T>(current_fork, payload_id).await
                };
                let (blob, payload_response) = tokio::join!(blob_fut, payload_fut);
                let (execution_payload, block_value) = payload_response.map(|payload_response| {
                    if payload_response.execution_payload_ref().fee_recipient() != payload_attributes.suggested_fee_recipient() {
                        error!(
                            self.log(),
                            "Inconsistent fee recipient";
                            "msg" => "The fee recipient returned from the Execution Engine differs \
                            from the suggested_fee_recipient set on the beacon node. This could \
                            indicate that fees are being diverted to another address. Please \
                            ensure that the value of suggested_fee_recipient is set correctly and \
                            that the Execution Engine is trusted.",
                            "fee_recipient" => ?payload_response.execution_payload_ref().fee_recipient(),
                            "suggested_fee_recipient" => ?payload_attributes.suggested_fee_recipient(),
                        );
                    }
                    if f(self, payload_response.execution_payload_ref()).is_some() {
                        warn!(
                            self.log(),
                            "Duplicate payload cached, this might indicate redundant proposal \
                                 attempts."
                        );
                    }
                    payload_response.into()
                })?;
                if let Some(blob) = blob.transpose()? {
                    // FIXME(sean) cache blobs
                    Ok(BlockProposalContents::PayloadAndBlobs {
                        payload: execution_payload.into(),
                        block_value,
                        blobs: blob.blobs,
                        kzg_commitments: blob.kzgs,
                    })
                } else {
                    Ok(BlockProposalContents::Payload {
                        payload: execution_payload.into(),
                        block_value,
                    })
                }
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Maps to the `engine_newPayload` JSON-RPC call.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Error::ConsensusFailure if some nodes return valid and some return invalid
    /// - Valid, if any nodes return valid.
    /// - Invalid, if any nodes return invalid.
    /// - Syncing, if any nodes return syncing.
    /// - An error, if all nodes return an error.
    pub async fn notify_new_payload(
        &self,
        execution_payload: &ExecutionPayload<T>,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::NEW_PAYLOAD],
        );

        trace!(
            self.log(),
            "Issuing engine_newPayload";
            "parent_hash" => ?execution_payload.parent_hash(),
            "block_hash" => ?execution_payload.block_hash(),
            "block_number" => execution_payload.block_number(),
        );

        let result = self
            .engine()
            .request(|engine| engine.api.new_payload(execution_payload.clone()))
            .await;

        if let Ok(status) = &result {
            metrics::inc_counter_vec(
                &metrics::EXECUTION_LAYER_PAYLOAD_STATUS,
                &["new_payload", status.status.into()],
            );
        }

        process_payload_status(execution_payload.block_hash(), result, self.log())
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Register that the given `validator_index` is going to produce a block at `slot`.
    ///
    /// The block will be built atop `head_block_root` and the EL will need to prepare an
    /// `ExecutionPayload` as defined by the given `payload_attributes`.
    pub async fn insert_proposer(
        &self,
        slot: Slot,
        head_block_root: Hash256,
        validator_index: u64,
        payload_attributes: PayloadAttributes,
    ) -> bool {
        let proposers_key = ProposerKey {
            slot,
            head_block_root,
        };

        let existing = self.proposers().write().await.insert(
            proposers_key,
            Proposer {
                validator_index,
                payload_attributes,
            },
        );

        if existing.is_none() {
            metrics::inc_counter(&metrics::EXECUTION_LAYER_PROPOSER_INSERTED);
        }

        existing.is_some()
    }

    /// If there has been a proposer registered via `Self::insert_proposer` with a matching `slot`
    /// `head_block_root`, then return the appropriate `PayloadAttributes` for inclusion in
    /// `forkchoiceUpdated` calls.
    pub async fn payload_attributes(
        &self,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Option<PayloadAttributes> {
        let proposers_key = ProposerKey {
            slot: current_slot,
            head_block_root,
        };

        let proposer = self.proposers().read().await.get(&proposers_key).cloned()?;

        debug!(
            self.log(),
            "Beacon proposer found";
            "payload_attributes" => ?proposer.payload_attributes,
            "head_block_root" => ?head_block_root,
            "slot" => current_slot,
            "validator_index" => proposer.validator_index,
        );

        Some(proposer.payload_attributes)
    }

    /// Maps to the `engine_consensusValidated` JSON-RPC call.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Error::ConsensusFailure if some nodes return valid and some return invalid
    /// - Valid, if any nodes return valid.
    /// - Invalid, if any nodes return invalid.
    /// - Syncing, if any nodes return syncing.
    /// - An error, if all nodes return an error.
    pub async fn notify_forkchoice_updated(
        &self,
        head_block_hash: ExecutionBlockHash,
        justified_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::FORKCHOICE_UPDATED],
        );

        debug!(
            self.log(),
            "Issuing engine_forkchoiceUpdated";
            "finalized_block_hash" => ?finalized_block_hash,
            "justified_block_hash" => ?justified_block_hash,
            "head_block_hash" => ?head_block_hash,
            "head_block_root" => ?head_block_root,
            "current_slot" => current_slot,
        );

        let next_slot = current_slot + 1;
        let payload_attributes = self.payload_attributes(next_slot, head_block_root).await;

        // Compute the "lookahead", the time between when the payload will be produced and now.
        if let Some(ref payload_attributes) = payload_attributes {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let timestamp = Duration::from_secs(payload_attributes.timestamp());
                if let Some(lookahead) = timestamp.checked_sub(now) {
                    metrics::observe_duration(
                        &metrics::EXECUTION_LAYER_PAYLOAD_ATTRIBUTES_LOOKAHEAD,
                        lookahead,
                    );
                } else {
                    debug!(
                        self.log(),
                        "Late payload attributes";
                        "timestamp" => ?timestamp,
                        "now" => ?now,
                    )
                }
            }
        }

        let forkchoice_state = ForkchoiceState {
            head_block_hash,
            safe_block_hash: justified_block_hash,
            finalized_block_hash,
        };

        self.engine()
            .set_latest_forkchoice_state(forkchoice_state)
            .await;

        let result = self
            .engine()
            .request(|engine| async move {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes, self.log())
                    .await
            })
            .await;

        if let Ok(status) = &result {
            metrics::inc_counter_vec(
                &metrics::EXECUTION_LAYER_PAYLOAD_STATUS,
                &["forkchoice_updated", status.payload_status.status.into()],
            );
        }

        process_payload_status(
            head_block_hash,
            result.map(|response| response.payload_status),
            self.log(),
        )
        .map_err(Box::new)
        .map_err(Error::EngineError)
    }

    pub async fn exchange_transition_configuration(&self, spec: &ChainSpec) -> Result<(), Error> {
        let local = TransitionConfigurationV1 {
            terminal_total_difficulty: spec.terminal_total_difficulty,
            terminal_block_hash: spec.terminal_block_hash,
            terminal_block_number: 0,
        };

        let result = self
            .engine()
            .request(|engine| engine.api.exchange_transition_configuration_v1(local))
            .await;

        match result {
            Ok(remote) => {
                if local.terminal_total_difficulty != remote.terminal_total_difficulty
                    || local.terminal_block_hash != remote.terminal_block_hash
                {
                    error!(
                        self.log(),
                        "Execution client config mismatch";
                        "msg" => "ensure lighthouse and the execution client are up-to-date and \
                                  configured consistently",
                        "remote" => ?remote,
                        "local" => ?local,
                    );
                    Err(Error::EngineError(Box::new(EngineError::Api {
                        error: ApiError::TransitionConfigurationMismatch,
                    })))
                } else {
                    debug!(
                        self.log(),
                        "Execution client config is OK";
                    );
                    Ok(())
                }
            }
            Err(e) => {
                error!(
                    self.log(),
                    "Unable to get transition config";
                    "error" => ?e,
                );
                Err(Error::EngineError(Box::new(e)))
            }
        }
    }

    /// Returns the execution engine capabilities resulting from a call to
    /// engine_exchangeCapabilities. If the capabilities cache is not populated,
    /// or if it is populated with a cached result of age >= `age_limit`, this
    /// method will fetch the result from the execution engine and populate the
    /// cache before returning it. Otherwise it will return a cached result from
    /// a previous call.
    ///
    /// Set `age_limit` to `None` to always return the cached result
    /// Set `age_limit` to `Some(Duration::ZERO)` to force fetching from EE
    pub async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, Error> {
        self.engine()
            .request(|engine| engine.get_engine_capabilities(age_limit))
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Used during block production to determine if the merge has been triggered.
    ///
    /// ## Specification
    ///
    /// `get_terminal_pow_block_hash`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md
    pub async fn get_terminal_pow_block_hash(
        &self,
        spec: &ChainSpec,
        timestamp: u64,
    ) -> Result<Option<ExecutionBlockHash>, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::GET_TERMINAL_POW_BLOCK_HASH],
        );

        let hash_opt = self
            .engine()
            .request(|engine| async move {
                let terminal_block_hash = spec.terminal_block_hash;
                if terminal_block_hash != ExecutionBlockHash::zero() {
                    if self
                        .get_pow_block(engine, terminal_block_hash)
                        .await?
                        .is_some()
                    {
                        return Ok(Some(terminal_block_hash));
                    } else {
                        return Ok(None);
                    }
                }

                let block = self.get_pow_block_at_total_difficulty(engine, spec).await?;
                if let Some(pow_block) = block {
                    // If `terminal_block.timestamp == transition_block.timestamp`,
                    // we violate the invariant that a block's timestamp must be
                    // strictly greater than its parent's timestamp.
                    // The execution layer will reject a fcu call with such payload
                    // attributes leading to a missed block.
                    // Hence, we return `None` in such a case.
                    if pow_block.timestamp >= timestamp {
                        return Ok(None);
                    }
                }
                Ok(block.map(|b| b.block_hash))
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)?;

        if let Some(hash) = &hash_opt {
            info!(
                self.log(),
                "Found terminal block hash";
                "terminal_block_hash_override" => ?spec.terminal_block_hash,
                "terminal_total_difficulty" => ?spec.terminal_total_difficulty,
                "block_hash" => ?hash,
            );
        }

        Ok(hash_opt)
    }

    /// This function should remain internal. External users should use
    /// `self.get_terminal_pow_block` instead, since it checks against the terminal block hash
    /// override.
    ///
    /// ## Specification
    ///
    /// `get_pow_block_at_terminal_total_difficulty`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md
    async fn get_pow_block_at_total_difficulty(
        &self,
        engine: &Engine,
        spec: &ChainSpec,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        let mut block = engine
            .api
            .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
            .await?
            .ok_or(ApiError::ExecutionHeadBlockNotFound)?;

        self.execution_blocks().await.put(block.block_hash, block);

        loop {
            let block_reached_ttd = block.total_difficulty >= spec.terminal_total_difficulty;
            if block_reached_ttd {
                if block.parent_hash == ExecutionBlockHash::zero() {
                    return Ok(Some(block));
                }
                let parent = self
                    .get_pow_block(engine, block.parent_hash)
                    .await?
                    .ok_or(ApiError::ExecutionBlockNotFound(block.parent_hash))?;
                let parent_reached_ttd = parent.total_difficulty >= spec.terminal_total_difficulty;

                if block_reached_ttd && !parent_reached_ttd {
                    return Ok(Some(block));
                } else {
                    block = parent;
                }
            } else {
                return Ok(None);
            }
        }
    }

    /// Used during block verification to check that a block correctly triggers the merge.
    ///
    /// ## Returns
    ///
    /// - `Some(true)` if the given `block_hash` is the terminal proof-of-work block.
    /// - `Some(false)` if the given `block_hash` is certainly *not* the terminal proof-of-work
    ///     block.
    /// - `None` if the `block_hash` or its parent were not present on the execution engine.
    /// - `Err(_)` if there was an error connecting to the execution engine.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Terminal, if any node indicates it is terminal.
    /// - Not terminal, if any node indicates it is non-terminal.
    /// - Block not found, if any node cannot find the block.
    /// - An error, if all nodes return an error.
    ///
    /// ## Specification
    ///
    /// `is_valid_terminal_pow_block`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/fork-choice.md
    pub async fn is_valid_terminal_pow_block_hash(
        &self,
        block_hash: ExecutionBlockHash,
        spec: &ChainSpec,
    ) -> Result<Option<bool>, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::IS_VALID_TERMINAL_POW_BLOCK_HASH],
        );

        self.engine()
            .request(|engine| async move {
                if let Some(pow_block) = self.get_pow_block(engine, block_hash).await? {
                    if let Some(pow_parent) =
                        self.get_pow_block(engine, pow_block.parent_hash).await?
                    {
                        return Ok(Some(
                            self.is_valid_terminal_pow_block(pow_block, pow_parent, spec),
                        ));
                    }
                }
                Ok(None)
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// This function should remain internal.
    ///
    /// External users should use `self.is_valid_terminal_pow_block_hash`.
    fn is_valid_terminal_pow_block(
        &self,
        block: ExecutionBlock,
        parent: ExecutionBlock,
        spec: &ChainSpec,
    ) -> bool {
        let is_total_difficulty_reached = block.total_difficulty >= spec.terminal_total_difficulty;
        let is_parent_total_difficulty_valid =
            parent.total_difficulty < spec.terminal_total_difficulty;
        is_total_difficulty_reached && is_parent_total_difficulty_valid
    }

    /// Maps to the `eth_getBlockByHash` JSON-RPC call.
    async fn get_pow_block(
        &self,
        engine: &Engine,
        hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        if let Some(cached) = self.execution_blocks().await.get(&hash).copied() {
            // The block was in the cache, no need to request it from the execution
            // engine.
            return Ok(Some(cached));
        }

        // The block was *not* in the cache, request it from the execution
        // engine and cache it for future reference.
        if let Some(block) = engine.api.get_block_by_hash(hash).await? {
            self.execution_blocks().await.put(hash, block);
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub async fn get_payload_by_block_hash(
        &self,
        hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionPayload<T>>, Error> {
        self.engine()
            .request(|engine| async move {
                self.get_payload_by_block_hash_from_engine(engine, hash, fork)
                    .await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    async fn get_payload_by_block_hash_from_engine(
        &self,
        engine: &Engine,
        hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionPayload<T>>, ApiError> {
        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_GET_PAYLOAD_BY_BLOCK_HASH);

        if hash == ExecutionBlockHash::zero() {
            return match fork {
                ForkName::Merge => Ok(Some(ExecutionPayloadMerge::default().into())),
                ForkName::Capella => Ok(Some(ExecutionPayloadCapella::default().into())),
                ForkName::Eip4844 => Ok(Some(ExecutionPayloadEip4844::default().into())),
                ForkName::Base | ForkName::Altair => Err(ApiError::UnsupportedForkVariant(
                    format!("called get_payload_by_block_hash_from_engine with {}", fork),
                )),
            };
        }

        let block = if let Some(block) = engine
            .api
            .get_block_by_hash_with_txns::<T>(hash, fork)
            .await?
        {
            block
        } else {
            return Ok(None);
        };

        let transactions = VariableList::new(
            block
                .transactions()
                .iter()
                .map(|transaction| VariableList::new(transaction.rlp().to_vec()))
                .collect::<Result<_, _>>()
                .map_err(ApiError::DeserializeTransaction)?,
        )
        .map_err(ApiError::DeserializeTransactions)?;

        let payload = match block {
            ExecutionBlockWithTransactions::Merge(merge_block) => {
                ExecutionPayload::Merge(ExecutionPayloadMerge {
                    parent_hash: merge_block.parent_hash,
                    fee_recipient: merge_block.fee_recipient,
                    state_root: merge_block.state_root,
                    receipts_root: merge_block.receipts_root,
                    logs_bloom: merge_block.logs_bloom,
                    prev_randao: merge_block.prev_randao,
                    block_number: merge_block.block_number,
                    gas_limit: merge_block.gas_limit,
                    gas_used: merge_block.gas_used,
                    timestamp: merge_block.timestamp,
                    extra_data: merge_block.extra_data,
                    base_fee_per_gas: merge_block.base_fee_per_gas,
                    block_hash: merge_block.block_hash,
                    transactions,
                })
            }
            ExecutionBlockWithTransactions::Capella(capella_block) => {
                let withdrawals = VariableList::new(
                    capella_block
                        .withdrawals
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )
                .map_err(ApiError::DeserializeWithdrawals)?;
                ExecutionPayload::Capella(ExecutionPayloadCapella {
                    parent_hash: capella_block.parent_hash,
                    fee_recipient: capella_block.fee_recipient,
                    state_root: capella_block.state_root,
                    receipts_root: capella_block.receipts_root,
                    logs_bloom: capella_block.logs_bloom,
                    prev_randao: capella_block.prev_randao,
                    block_number: capella_block.block_number,
                    gas_limit: capella_block.gas_limit,
                    gas_used: capella_block.gas_used,
                    timestamp: capella_block.timestamp,
                    extra_data: capella_block.extra_data,
                    base_fee_per_gas: capella_block.base_fee_per_gas,
                    block_hash: capella_block.block_hash,
                    transactions,
                    withdrawals,
                })
            }
            ExecutionBlockWithTransactions::Eip4844(eip4844_block) => {
                let withdrawals = VariableList::new(
                    eip4844_block
                        .withdrawals
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )
                .map_err(ApiError::DeserializeWithdrawals)?;
                ExecutionPayload::Eip4844(ExecutionPayloadEip4844 {
                    parent_hash: eip4844_block.parent_hash,
                    fee_recipient: eip4844_block.fee_recipient,
                    state_root: eip4844_block.state_root,
                    receipts_root: eip4844_block.receipts_root,
                    logs_bloom: eip4844_block.logs_bloom,
                    prev_randao: eip4844_block.prev_randao,
                    block_number: eip4844_block.block_number,
                    gas_limit: eip4844_block.gas_limit,
                    gas_used: eip4844_block.gas_used,
                    timestamp: eip4844_block.timestamp,
                    extra_data: eip4844_block.extra_data,
                    base_fee_per_gas: eip4844_block.base_fee_per_gas,
                    excess_data_gas: eip4844_block.excess_data_gas,
                    block_hash: eip4844_block.block_hash,
                    transactions,
                    withdrawals,
                })
            }
        };

        Ok(Some(payload))
    }
}

#[allow(unused)]
#[derive(AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum InvalidBuilderPayload {
    LowValue {
        profit_threshold: Uint256,
        payload_value: Uint256,
    },
    ParentHash {
        payload: ExecutionBlockHash,
        expected: ExecutionBlockHash,
    },
    PrevRandao {
        payload: Hash256,
        expected: Hash256,
    },
    Timestamp {
        payload: u64,
        expected: u64,
    },
    BlockNumber {
        payload: u64,
        expected: Option<u64>,
    },
    Fork {
        payload: Option<ForkName>,
        expected: ForkName,
    },
    Signature {
        signature: Signature,
        pubkey: PublicKeyBytes,
    },
    WithdrawalsRoot {
        payload: Option<Hash256>,
        expected: Option<Hash256>,
    },
}

#[allow(unused)]
impl InvalidBuilderPayload {
    /// Returns `true` if a payload is objectively invalid and should never be included on chain.
    fn payload_invalid(&self) -> bool {
        match self {
            // A low-value payload isn't invalid, it should just be avoided if possible.
            InvalidBuilderPayload::LowValue { .. } => false,
            InvalidBuilderPayload::ParentHash { .. } => true,
            InvalidBuilderPayload::PrevRandao { .. } => true,
            InvalidBuilderPayload::Timestamp { .. } => true,
            InvalidBuilderPayload::BlockNumber { .. } => true,
            InvalidBuilderPayload::Fork { .. } => true,
            InvalidBuilderPayload::Signature { .. } => true,
            InvalidBuilderPayload::WithdrawalsRoot { .. } => true,
        }
    }
}

impl fmt::Display for InvalidBuilderPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidBuilderPayload::LowValue {
                profit_threshold,
                payload_value,
            } => write!(
                f,
                "payload value of {} does not meet user-configured profit-threshold of {}",
                payload_value, profit_threshold
            ),
            InvalidBuilderPayload::ParentHash { payload, expected } => {
                write!(f, "payload block hash was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::PrevRandao { payload, expected } => {
                write!(f, "payload prev randao was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::Timestamp { payload, expected } => {
                write!(f, "payload timestamp was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::BlockNumber { payload, expected } => {
                write!(f, "payload block number was {} not {:?}", payload, expected)
            }
            InvalidBuilderPayload::Fork { payload, expected } => {
                write!(f, "payload fork was {:?} not {}", payload, expected)
            }
            InvalidBuilderPayload::Signature { signature, pubkey } => write!(
                f,
                "invalid payload signature {} for pubkey {}",
                signature, pubkey
            ),
            InvalidBuilderPayload::WithdrawalsRoot { payload, expected } => {
                let opt_string = |opt_hash: &Option<Hash256>| {
                    opt_hash
                        .map(|hash| hash.to_string())
                        .unwrap_or_else(|| "None".to_string())
                };
                write!(
                    f,
                    "payload withdrawals root was {} not {}",
                    opt_string(payload),
                    opt_string(expected)
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockExecutionLayer as GenericMockExecutionLayer;
    use task_executor::test_utils::TestRuntime;
    use types::MainnetEthSpec;

    type MockExecutionLayer = GenericMockExecutionLayer<MainnetEthSpec>;

    #[tokio::test]
    async fn produce_three_valid_pos_execution_blocks() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .produce_valid_execution_payload_on_head()
            .await
            .produce_valid_execution_payload_on_head()
            .await
            .produce_valid_execution_payload_on_head()
            .await;
    }

    #[tokio::test]
    async fn test_forked_terminal_block() {
        let runtime = TestRuntime::default();
        let (mock, block_hash) = MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .produce_forked_pow_block();
        assert!(mock
            .el
            .is_valid_terminal_pow_block_hash(block_hash, &mock.spec)
            .await
            .unwrap()
            .unwrap());
    }

    #[tokio::test]
    async fn finds_valid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engine().upcheck().await;
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    None
                )
            })
            .await
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    Some(terminal_block.unwrap().block_hash)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_terminal_block_with_equal_timestamp() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engine().upcheck().await;
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    None
                )
            })
            .await
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                let timestamp = terminal_block.as_ref().map(|b| b.timestamp).unwrap();
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp)
                        .await
                        .unwrap(),
                    None
                )
            })
            .await;
    }

    #[tokio::test]
    async fn verifies_valid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                el.engine().upcheck().await;
                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(terminal_block.unwrap().block_hash, &spec)
                        .await
                        .unwrap(),
                    Some(true)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_invalid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                el.engine().upcheck().await;
                let invalid_terminal_block = terminal_block.unwrap().parent_hash;

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(invalid_terminal_block, &spec)
                        .await
                        .unwrap(),
                    Some(false)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_unknown_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engine().upcheck().await;
                let missing_terminal_block = ExecutionBlockHash::repeat_byte(42);

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(missing_terminal_block, &spec)
                        .await
                        .unwrap(),
                    None
                )
            })
            .await;
    }
}

fn noop<T: EthSpec>(
    _: &ExecutionLayer<T>,
    _: ExecutionPayloadRef<T>,
) -> Option<ExecutionPayload<T>> {
    None
}

#[cfg(test)]
fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}