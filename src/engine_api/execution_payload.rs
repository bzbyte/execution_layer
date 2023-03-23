use crate::engine_api::ethspec::EthSpec;
use crate::engine_api::json_structures::ExecutionBlockHash;
use crate::engine_api::withdrawal::Withdrawal;
use crate::engine_api::Error;
use crate::serde_utils as eth2_serde_utils;
use derivative::Derivative;
use ethereum_types::Address;
pub use ethereum_types::H256 as Hash256;
pub use ethereum_types::U256 as Uint256;
use serde_derive::{Deserialize, Serialize};
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;

pub type Transaction<N> = VariableList<u8, N>;
pub type Transactions<T> = VariableList<
    Transaction<<T as EthSpec>::MaxBytesPerTransaction>,
    <T as EthSpec>::MaxTransactionsPerPayload,
>;

pub type Withdrawals<T> = VariableList<Withdrawal, <T as EthSpec>::MaxWithdrawalsPerPayload>;

#[superstruct(
    variants(Merge, Capella, Eip4844),
    variant_attributes(
        derive(Default, Debug, Clone, Serialize, Deserialize, Derivative,),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    map_into(FullPayload, BlindedPayload),
    map_ref_into(ExecutionPayloadHeader)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec", untagged)]
pub struct ExecutionPayload<T: EthSpec> {
    #[superstruct(getter(copy))]
    pub parent_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(getter(copy))]
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub base_fee_per_gas: Uint256,
    #[superstruct(only(Eip4844))]
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub excess_data_gas: Uint256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<T>,
    #[superstruct(only(Capella, Eip4844))]
    pub withdrawals: Withdrawals<T>,
}

impl<'a, T: EthSpec> ExecutionPayloadRef<'a, T> {
    // this emulates clone on a normal reference type
    pub fn clone_from_ref(&self) -> ExecutionPayload<T> {
        map_execution_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}
