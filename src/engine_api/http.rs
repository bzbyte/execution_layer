//! Contains an implementation of `EngineAPI` using the JSON-RPC API via HTTP.

use super::*;
use crate::engine_api::auth::Auth;
use crate::engine_api::json_structures::*;
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashSet;
use tokio::sync::Mutex;
use std::fmt::{self, Display, Formatter};

use std::time::{Duration, Instant};
use types::EthSpec;

pub use reqwest::Client;

const STATIC_ID: u32 = 1;
pub const JSONRPC_VERSION: &str = "2.0";

pub const RETURN_FULL_TRANSACTION_OBJECTS: bool = false;

pub const ETH_GET_BLOCK_BY_NUMBER: &str = "eth_getBlockByNumber";
pub const ETH_GET_BLOCK_BY_NUMBER_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_GET_BLOCK_BY_HASH: &str = "eth_getBlockByHash";
pub const ETH_GET_BLOCK_BY_HASH_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_SYNCING: &str = "eth_syncing";
pub const ETH_SYNCING_TIMEOUT: Duration = Duration::from_secs(1);

pub const ENGINE_NEW_PAYLOAD_V1: &str = "engine_newPayloadV1";
pub const ENGINE_NEW_PAYLOAD_V2: &str = "engine_newPayloadV2";
pub const ENGINE_NEW_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(8);

pub const ENGINE_GET_PAYLOAD_V1: &str = "engine_getPayloadV1";
pub const ENGINE_GET_PAYLOAD_V2: &str = "engine_getPayloadV2";
pub const ENGINE_GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_GET_BLOBS_BUNDLE_V1: &str = "engine_getBlobsBundleV1";
pub const ENGINE_GET_BLOBS_BUNDLE_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_FORKCHOICE_UPDATED_V1: &str = "engine_forkchoiceUpdatedV1";
pub const ENGINE_FORKCHOICE_UPDATED_V2: &str = "engine_forkchoiceUpdatedV2";
pub const ENGINE_FORKCHOICE_UPDATED_TIMEOUT: Duration = Duration::from_secs(8);

pub const ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1: &str =
    "engine_exchangeTransitionConfigurationV1";
pub const ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1_TIMEOUT: Duration = Duration::from_secs(1);

pub const ENGINE_EXCHANGE_CAPABILITIES: &str = "engine_exchangeCapabilities";
pub const ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);

/// This error is returned during a `chainId` call by Geth.
pub const EIP155_ERROR_STR: &str = "chain not synced beyond EIP-155 replay-protection fork block";
/// This code is returned by all clients when a method is not supported
/// (verified geth, nethermind, erigon, besu)
pub const METHOD_NOT_FOUND_CODE: i64 = -32601;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkName {
    Base,
    Altair,
    Merge,
    Capella,
    Eip4844,
}

impl Display for ForkName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ForkName::Base => "phase0".fmt(f),
            ForkName::Altair => "altair".fmt(f),
            ForkName::Merge => "bellatrix".fmt(f),
            ForkName::Capella => "capella".fmt(f),
            ForkName::Eip4844 => "eip4844".fmt(f),
        }
    }
}


pub static LIGHTHOUSE_CAPABILITIES: &[&str] = &[
    ENGINE_NEW_PAYLOAD_V1,
    ENGINE_NEW_PAYLOAD_V2,
    ENGINE_GET_PAYLOAD_V1,
    ENGINE_GET_PAYLOAD_V2,
    ENGINE_FORKCHOICE_UPDATED_V1,
    ENGINE_FORKCHOICE_UPDATED_V2,
    ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1,
];

/// This is necessary because a user might run a capella-enabled version of
/// lighthouse before they update to a capella-enabled execution engine.
// TODO (mark): rip this out once we are post-capella on mainnet
pub static PRE_CAPELLA_ENGINE_CAPABILITIES: EngineCapabilities = EngineCapabilities {
    new_payload_v1: true,
    new_payload_v2: false,
    forkchoice_updated_v1: true,
    forkchoice_updated_v2: false,
    get_payload_v1: true,
    get_payload_v2: false,
    exchange_transition_configuration_v1: true,
};

/// Contains subset of the HTTP JSON-RPC methods used to query an execution node for
/// state of the deposit contract.
pub mod deposit_methods {
    use crate::engine_api::http::HttpJsonRpc;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::fmt;
    use std::str::FromStr;
    use std::time::Duration;
    use types::Hash256;

    /// `keccak("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`
    pub const DEPOSIT_EVENT_TOPIC: &str =
        "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
    /// `keccak("get_deposit_root()")[0..4]`
    pub const DEPOSIT_ROOT_FN_SIGNATURE: &str = "0xc5f2892f";
    /// `keccak("get_deposit_count()")[0..4]`
    pub const DEPOSIT_COUNT_FN_SIGNATURE: &str = "0x621fd130";

    /// Number of bytes in deposit contract deposit root response.
    pub const DEPOSIT_COUNT_RESPONSE_BYTES: usize = 96;
    /// Number of bytes in deposit contract deposit root (value only).
    pub const DEPOSIT_ROOT_BYTES: usize = 32;

    /// Represents an eth1 chain/network id.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum Eth1Id {
        Goerli,
        Mainnet,
        Custom(u64),
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct Block {
        pub hash: Hash256,
        pub timestamp: u64,
        pub number: u64,
    }

    /// Used to identify a block when querying the Eth1 node.
    #[derive(Clone, Copy)]
    pub enum BlockQuery {
        Number(u64),
        Hash(Hash256),
        Latest,
    }

    impl Into<u64> for Eth1Id {
        fn into(self) -> u64 {
            match self {
                Eth1Id::Mainnet => 1,
                Eth1Id::Goerli => 5,
                Eth1Id::Custom(id) => id,
            }
        }
    }

    impl From<u64> for Eth1Id {
        fn from(id: u64) -> Self {
            let into = |x: Eth1Id| -> u64 { x.into() };
            match id {
                id if id == into(Eth1Id::Mainnet) => Eth1Id::Mainnet,
                id if id == into(Eth1Id::Goerli) => Eth1Id::Goerli,
                id => Eth1Id::Custom(id),
            }
        }
    }

    impl FromStr for Eth1Id {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.parse::<u64>()
                .map(Into::into)
                .map_err(|e| format!("Failed to parse eth1 network id {}", e))
        }
    }

    /// Represents an error received from a remote procecdure call.
    #[derive(Debug, Serialize, Deserialize)]
    pub enum RpcError {
        NoResultField,
        Eip155Error,
        InvalidJson(String),
        Error(String),
    }

    impl fmt::Display for RpcError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                RpcError::NoResultField => write!(f, "No result field in response"),
                RpcError::Eip155Error => write!(f, "Not synced past EIP-155"),
                RpcError::InvalidJson(e) => write!(f, "Malformed JSON received: {}", e),
                RpcError::Error(s) => write!(f, "{}", s),
            }
        }
    }

    impl From<RpcError> for String {
        fn from(e: RpcError) -> String {
            e.to_string()
        }
    }

    /// Parses a `0x`-prefixed, **big-endian** hex string as a u64.
    ///
    /// Note: the JSON-RPC encodes integers as big-endian. The deposit contract uses little-endian.
    /// Therefore, this function is only useful for numbers encoded by the JSON RPC.
    ///
    /// E.g., `0x01 == 1`
    fn hex_to_u64_be(hex: &str) -> Result<u64, String> {
        u64::from_str_radix(strip_prefix(hex)?, 16)
            .map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
    }

    /// Parses a `0x`-prefixed, big-endian hex string as bytes.
    ///
    /// E.g., `0x0102 == vec![1, 2]`
    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
        hex::decode(strip_prefix(hex)?)
            .map_err(|e| format!("Failed to parse hex as bytes: {:?}", e))
    }

    /// Removes the `0x` prefix from some bytes. Returns an error if the prefix is not present.
    fn strip_prefix(hex: &str) -> Result<&str, String> {
        if let Some(stripped) = hex.strip_prefix("0x") {
            Ok(stripped)
        } else {
            Err("Hex string did not start with `0x`".to_string())
        }
    }

    impl HttpJsonRpc {
        /// Get the eth1 chain id of the given endpoint.
        pub async fn get_chain_id(&self, timeout: Duration) -> Result<Eth1Id, String> {
            let chain_id: String = self
                .rpc_request("eth_chainId", json!([]), timeout)
                .await
                .map_err(|e| format!("eth_chainId call failed {:?}", e))?;
            hex_to_u64_be(chain_id.as_str()).map(|id| id.into())
        }

        /// Returns the current block number.
        pub async fn get_block_number(&self, timeout: Duration) -> Result<u64, String> {
            let response: String = self
                .rpc_request("eth_blockNumber", json!([]), timeout)
                .await
                .map_err(|e| format!("eth_blockNumber call failed {:?}", e))?;
            hex_to_u64_be(response.as_str())
                .map_err(|e| format!("Failed to get block number: {}", e))
        }

        /// Gets a block hash by block number.
        pub async fn get_block(
            &self,
            query: BlockQuery,
            timeout: Duration,
        ) -> Result<Block, String> {
            let (method, query_param) = match query {
                BlockQuery::Number(block_number) => {
                    ("eth_getBlockByNumber", format!("0x{:x}", block_number))
                }
                BlockQuery::Hash(block_hash) => ("eth_getBlockByHash", format!("{:?}", block_hash)),
                BlockQuery::Latest => ("eth_getBlockByNumber", "latest".to_string()),
            };
            let params = json!([
                query_param,
                false // do not return full tx objects.
            ]);

            let response: Value = self
                .rpc_request(method, params, timeout)
                .await
                .map_err(|e| format!("{} call failed {:?}", method, e))?;

            let hash: Vec<u8> = hex_to_bytes(
                response
                    .get("hash")
                    .ok_or("No hash for block")?
                    .as_str()
                    .ok_or("Block hash was not string")?,
            )?;
            let hash: Hash256 = if hash.len() == 32 {
                Hash256::from_slice(&hash)
            } else {
                return Err(format!("Block hash was not 32 bytes: {:?}", hash));
            };

            let timestamp = hex_to_u64_be(
                response
                    .get("timestamp")
                    .ok_or("No timestamp for block")?
                    .as_str()
                    .ok_or("Block timestamp was not string")?,
            )?;

            let number = hex_to_u64_be(
                response
                    .get("number")
                    .ok_or("No number for block")?
                    .as_str()
                    .ok_or("Block number was not string")?,
            )?;

            if number <= usize::max_value() as u64 {
                Ok(Block {
                    hash,
                    timestamp,
                    number,
                })
            } else {
                Err(format!("Block number {} is larger than a usize", number))
            }
            .map_err(|e| format!("Failed to get block number: {}", e))
        }

        /// Returns the value of the `get_deposit_count()` call at the given `address` for the given
        /// `block_number`.
        ///
        /// Assumes that the `address` has the same ABI as the eth2 deposit contract.
        pub async fn get_deposit_count(
            &self,
            address: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<u64>, String> {
            let result = self
                .call(address, DEPOSIT_COUNT_FN_SIGNATURE, block_number, timeout)
                .await?;
            match result {
                None => Err("Deposit root response was none".to_string()),
                Some(bytes) => {
                    if bytes.is_empty() {
                        Ok(None)
                    } else if bytes.len() == DEPOSIT_COUNT_RESPONSE_BYTES {
                        let mut array = [0; 8];
                        array.copy_from_slice(&bytes[32 + 32..32 + 32 + 8]);
                        Ok(Some(u64::from_le_bytes(array)))
                    } else {
                        Err(format!(
                            "Deposit count response was not {} bytes: {:?}",
                            DEPOSIT_COUNT_RESPONSE_BYTES, bytes
                        ))
                    }
                }
            }
        }

        /// Returns the value of the `get_hash_tree_root()` call at the given `block_number`.
        ///
        /// Assumes that the `address` has the same ABI as the eth2 deposit contract.
        pub async fn get_deposit_root(
            &self,
            address: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<Hash256>, String> {
            let result = self
                .call(address, DEPOSIT_ROOT_FN_SIGNATURE, block_number, timeout)
                .await?;
            match result {
                None => Err("Deposit root response was none".to_string()),
                Some(bytes) => {
                    if bytes.is_empty() {
                        Ok(None)
                    } else if bytes.len() == DEPOSIT_ROOT_BYTES {
                        Ok(Some(Hash256::from_slice(&bytes)))
                    } else {
                        Err(format!(
                            "Deposit root response was not {} bytes: {:?}",
                            DEPOSIT_ROOT_BYTES, bytes
                        ))
                    }
                }
            }
        }

        /// Performs a instant, no-transaction call to the contract `address` with the given `0x`-prefixed
        /// `hex_data`.
        ///
        /// Returns bytes, if any.
        async fn call(
            &self,
            address: &str,
            hex_data: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<Vec<u8>>, String> {
            let params = json! ([
                {
                    "to": address,
                    "data": hex_data,
                },
                format!("0x{:x}", block_number)
            ]);

            let response: Option<String> = self
                .rpc_request("eth_call", params, timeout)
                .await
                .map_err(|e| format!("eth_call call failed {:?}", e))?;

            response.map(|s| hex_to_bytes(&s)).transpose()
        }

        /*
        /// Returns logs for the `DEPOSIT_EVENT_TOPIC`, for the given `address` in the given
        /// `block_height_range`.
        ///
        /// It's not clear from the Ethereum JSON-RPC docs if this range is inclusive or not.
        pub async fn get_deposit_logs_in_range(
            &self,
            address: &str,
            block_height_range: Range<u64>,
            timeout: Duration,
        ) -> Result<Vec<Log>, String> {
            let params = json! ([{
                "address": address,
                "topics": [DEPOSIT_EVENT_TOPIC],
                "fromBlock": format!("0x{:x}", block_height_range.start),
                "toBlock": format!("0x{:x}", block_height_range.end),
            }]);

            let response: Value = self
                .rpc_request("eth_getLogs", params, timeout)
                .await
                .map_err(|e| format!("eth_getLogs call failed {:?}", e))?;
            response
                .as_array()
                .cloned()
                .ok_or("'result' value was not an array")?
                .into_iter()
                .map(|value| {
                    let block_number = value
                        .get("blockNumber")
                        .ok_or("No block number field in log")?
                        .as_str()
                        .ok_or("Block number was not string")?;

                    let data = value
                        .get("data")
                        .ok_or("No block number field in log")?
                        .as_str()
                        .ok_or("Data was not string")?;

                    Ok(Log {
                        block_number: hex_to_u64_be(block_number)?,
                        data: hex_to_bytes(data)?,
                    })
                })
                .collect::<Result<Vec<Log>, String>>()
                .map_err(|e| format!("Failed to get logs in range: {}", e))
        }*/
    }
}

#[derive(Clone, Debug)]
pub struct CapabilitiesCacheEntry {
    engine_capabilities: EngineCapabilities,
    fetch_time: Instant,
}

impl CapabilitiesCacheEntry {
    pub fn new(engine_capabilities: EngineCapabilities) -> Self {
        Self {
            engine_capabilities,
            fetch_time: Instant::now(),
        }
    }

    pub fn engine_capabilities(&self) -> EngineCapabilities {
        self.engine_capabilities
    }

    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.fetch_time)
    }

    /// returns `true` if the entry's age is >= age_limit
    pub fn older_than(&self, age_limit: Option<Duration>) -> bool {
        age_limit.map_or(false, |limit| self.age() >= limit)
    }
}

pub struct HttpJsonRpc {
    pub client: Client,
    pub url: SensitiveUrl,
    pub execution_timeout_multiplier: u32,
    pub engine_capabilities_cache: Mutex<Option<CapabilitiesCacheEntry>>,
    auth: Option<Auth>,
}

impl HttpJsonRpc {
    pub fn new(
        url: SensitiveUrl,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: Client::builder().build()?,
            url,
            execution_timeout_multiplier: execution_timeout_multiplier.unwrap_or(1),
            engine_capabilities_cache: Mutex::new(None),
            auth: None,
        })
    }

    pub fn new_with_auth(
        url: SensitiveUrl,
        auth: Auth,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: Client::builder().build()?,
            url,
            execution_timeout_multiplier: execution_timeout_multiplier.unwrap_or(1),
            engine_capabilities_cache: Mutex::new(None),
            auth: Some(auth),
        })
    }

    pub async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<D, Error> {
        let body = JsonRequestBody {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: json!(STATIC_ID),
        };

        let mut request = self
            .client
            .post(self.url.full.clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        // Generate and add a jwt token to the header if auth is defined.
        if let Some(auth) = &self.auth {
            request = request.bearer_auth(auth.generate_token()?);
        };

        let body: JsonResponseBody = request.send().await?.error_for_status()?.json().await?;

        match (body.result, body.error) {
            (result, None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.message.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Failure)
                } else {
                    Err(Error::ServerMessage {
                        code: error.code,
                        message: error.message,
                    })
                }
            }
        }
    }
}

impl std::fmt::Display for HttpJsonRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, auth={}", self.url, self.auth.is_some())
    }
}

impl HttpJsonRpc {
    pub async fn upcheck(&self) -> Result<(), Error> {
        let result: serde_json::Value = self
            .rpc_request(
                ETH_SYNCING,
                json!([]),
                ETH_SYNCING_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        /*
         * TODO
         *
         * Check the network and chain ids. We omit this to save time for the merge f2f and since it
         * also seems like it might get annoying during development.
         */
        match result.as_bool() {
            Some(false) => Ok(()),
            _ => Err(Error::IsSyncing),
        }
    }

    pub async fn get_block_by_number<'a>(
        &self,
        query: BlockByNumberQuery<'a>,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([query, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(
            ETH_GET_BLOCK_BY_NUMBER,
            params,
            ETH_GET_BLOCK_BY_NUMBER_TIMEOUT * self.execution_timeout_multiplier,
        )
        .await
    }

    pub async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([block_hash, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(
            ETH_GET_BLOCK_BY_HASH,
            params,
            ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
        )
        .await
    }

    pub async fn get_block_by_hash_with_txns<T: EthSpec>(
        &self,
        block_hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionBlockWithTransactions<T>>, Error> {
        let params = json!([block_hash, true]);
        Ok(Some(match fork {
            ForkName::Merge => ExecutionBlockWithTransactions::Merge(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Capella => ExecutionBlockWithTransactions::Capella(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Eip4844 => ExecutionBlockWithTransactions::Eip4844(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Base | ForkName::Altair => {
                return Err(Error::UnsupportedForkVariant(format!(
                    "called get_block_by_hash_with_txns with fork {:?}",
                    fork
                )))
            }
        }))
    }

    pub async fn new_payload_v1<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V1,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn new_payload_v2<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V2,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn get_payload_v1<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<T>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        let payload_v1: JsonExecutionPayloadV1<T> = self
            .rpc_request(
                ENGINE_GET_PAYLOAD_V1,
                params,
                ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(GetPayloadResponse::Merge(GetPayloadResponseMerge {
            execution_payload: payload_v1.into(),
            // Set the V1 payload values from the EE to be zero. This simulates
            // the pre-block-value functionality of always choosing the builder
            // block.
            block_value: Uint256::zero(),
        }))
    }

    pub async fn get_payload_v2<T: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<T>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        match fork_name {
            ForkName::Merge => {
                let response: JsonGetPayloadResponseV1<T> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V2,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V1(response).into())
            }
            ForkName::Capella => {
                let response: JsonGetPayloadResponseV2<T> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V2,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V2(response).into())
            }
            ForkName::Base | ForkName::Altair | ForkName::Eip4844 => Err(
                Error::UnsupportedForkVariant(format!("called get_payload_v2 with {}", fork_name)),
            ),
        }
    }

    pub async fn get_json_payload_v1<T: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<GetJsonPayloadResponse<T>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        let payload_v1: JsonExecutionPayloadV1<T> = self
            .rpc_request(
                ENGINE_GET_PAYLOAD_V1,
                params,
                ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        // Set the V1 payload values from the EE to be zero. This simulates
        // the pre-block-value functionality of always choosing the builder
        // block.
        Ok(GetJsonPayloadResponse::V1(payload_v1, Uint256::zero()))
    }

    pub async fn forkchoice_updated_v2(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let params = json!([
            JsonForkchoiceStateV1::from(forkchoice_state),
            payload_attributes.map(JsonPayloadAttributes::from)
        ]);

        let response: JsonForkchoiceUpdatedV1Response = self
            .rpc_request(
                ENGINE_FORKCHOICE_UPDATED_V2,
                params,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn exchange_transition_configuration_v1(
        &self,
        transition_configuration: TransitionConfigurationV1,
    ) -> Result<TransitionConfigurationV1, Error> {
        let params = json!([transition_configuration]);

        let response = self
            .rpc_request(
                ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1,
                params,
                ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1_TIMEOUT
                    * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response)
    }

    pub async fn exchange_capabilities(&self) -> Result<EngineCapabilities, Error> {
        let params = json!([LIGHTHOUSE_CAPABILITIES]);

        let response: Result<HashSet<String>, _> = self
            .rpc_request(
                ENGINE_EXCHANGE_CAPABILITIES,
                params,
                ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await;

        match response {
            // TODO (mark): rip this out once we are post capella on mainnet
            Err(error) => match error {
                Error::ServerMessage { code, message: _ } if code == METHOD_NOT_FOUND_CODE => {
                    Ok(PRE_CAPELLA_ENGINE_CAPABILITIES)
                }
                _ => Err(error),
            },
            Ok(capabilities) => Ok(EngineCapabilities {
                new_payload_v1: capabilities.contains(ENGINE_NEW_PAYLOAD_V1),
                new_payload_v2: capabilities.contains(ENGINE_NEW_PAYLOAD_V2),
                forkchoice_updated_v1: capabilities.contains(ENGINE_FORKCHOICE_UPDATED_V1),
                forkchoice_updated_v2: capabilities.contains(ENGINE_FORKCHOICE_UPDATED_V2),
                get_payload_v1: capabilities.contains(ENGINE_GET_PAYLOAD_V1),
                get_payload_v2: capabilities.contains(ENGINE_GET_PAYLOAD_V2),
                exchange_transition_configuration_v1: capabilities
                    .contains(ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1),
            }),
        }
    }

    pub async fn clear_exchange_capabilties_cache(&self) {
        *self.engine_capabilities_cache.lock().await = None;
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
        let mut lock = self.engine_capabilities_cache.lock().await;

        if let Some(lock) = lock.as_ref().filter(|entry| !entry.older_than(age_limit)) {
            Ok(lock.engine_capabilities())
        } else {
            let engine_capabilities = self.exchange_capabilities().await?;
            *lock = Some(CapabilitiesCacheEntry::new(engine_capabilities));
            Ok(engine_capabilities)
        }
    }

    // automatically selects the latest version of
    // new_payload that the execution engine supports
    pub async fn new_payload<T: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<T>,
    ) -> Result<PayloadStatusV1, Error> {
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        if engine_capabilities.new_payload_v2 {
            self.new_payload_v2(execution_payload).await
        } else if engine_capabilities.new_payload_v1 {
            self.new_payload_v1(execution_payload).await
        } else {
            Err(Error::RequiredMethodUnsupported("engine_newPayload"))
        }
    }

    // automatically selects the latest version of
    // get_payload that the execution engine supports
    pub async fn get_payload<T: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<T>, Error> {
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        if engine_capabilities.get_payload_v2 {
            self.get_payload_v2(fork_name, payload_id).await
        } else if engine_capabilities.new_payload_v1 {
            self.get_payload_v1(payload_id).await
        } else {
            Err(Error::RequiredMethodUnsupported("engine_getPayload"))
        }
    }
}
