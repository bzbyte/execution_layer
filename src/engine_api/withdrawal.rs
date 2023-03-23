use serde_derive::{Deserialize, Serialize};
use ethereum_types::Address;
use crate::serde_utils as eth2_serde_utils;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
)]
pub struct Withdrawal {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub amount: u64,
}
