use crate::ExecutionLayer;
pub use ethereum_consensus::state_transition::Context;
use ethereum_consensus::{
    crypto::{SecretKey, Signature},
    primitives::{BlsPublicKey, BlsSignature, ExecutionAddress, Hash32, Root, U256},
    state_transition::Error,
};
use mev_rs::{
    bellatrix::SignedBuilderBid as SignedBuilderBidBellatrix,
    capella::SignedBuilderBid as SignedBuilderBidCapella, sign_builder_message,
    BlindedBlockProviderError, BuilderBid, SignedBuilderBid, SignedValidatorRegistration,
};
use parking_lot::RwLock;

use ssz::{Decode, Encode};
use ssz_rs::SimpleSerialize;
use std::collections::HashMap;
use std::fmt::Debug;

use std::sync::Arc;

use types::{Address, ChainSpec, EthSpec, Hash256, Uint256};

#[derive(Clone)]
pub enum Operation {
    FeeRecipient(Address),
    GasLimit(usize),
    Value(Uint256),
    ParentHash(Hash256),
    PrevRandao(Hash256),
    BlockNumber(usize),
    Timestamp(usize),
    WithdrawalsRoot(Hash256),
}

#[allow(dead_code)]
impl Operation {
    fn apply<B: BidStuff>(self, bid: &mut B) -> Result<(), BlindedBlockProviderError> {
        match self {
            Operation::FeeRecipient(fee_recipient) => {
                *bid.fee_recipient_mut() = to_ssz_rs(&fee_recipient)?
            }
            Operation::GasLimit(gas_limit) => *bid.gas_limit_mut() = gas_limit as u64,
            Operation::Value(value) => *bid.value_mut() = to_ssz_rs(&value)?,
            Operation::ParentHash(parent_hash) => *bid.parent_hash_mut() = to_ssz_rs(&parent_hash)?,
            Operation::PrevRandao(prev_randao) => *bid.prev_randao_mut() = to_ssz_rs(&prev_randao)?,
            Operation::BlockNumber(block_number) => *bid.block_number_mut() = block_number as u64,
            Operation::Timestamp(timestamp) => *bid.timestamp_mut() = timestamp as u64,
            Operation::WithdrawalsRoot(root) => *bid.withdrawals_root_mut()? = to_ssz_rs(&root)?,
        }
        Ok(())
    }
}

// contains functions we need for BuilderBids.. not sure what to call this
pub trait BidStuff {
    fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress;
    fn gas_limit_mut(&mut self) -> &mut u64;
    fn value_mut(&mut self) -> &mut U256;
    fn parent_hash_mut(&mut self) -> &mut Hash32;
    fn prev_randao_mut(&mut self) -> &mut Hash32;
    fn block_number_mut(&mut self) -> &mut u64;
    fn timestamp_mut(&mut self) -> &mut u64;
    fn withdrawals_root_mut(&mut self) -> Result<&mut Root, BlindedBlockProviderError>;

    fn sign_builder_message(
        &mut self,
        signing_key: &SecretKey,
        context: &Context,
    ) -> Result<BlsSignature, Error>;

    fn to_signed_bid(self, signature: BlsSignature) -> SignedBuilderBid;
}

impl BidStuff for BuilderBid {
    fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.fee_recipient,
            Self::Capella(bid) => &mut bid.header.fee_recipient,
        }
    }

    fn gas_limit_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.gas_limit,
            Self::Capella(bid) => &mut bid.header.gas_limit,
        }
    }

    fn value_mut(&mut self) -> &mut U256 {
        match self {
            Self::Bellatrix(bid) => &mut bid.value,
            Self::Capella(bid) => &mut bid.value,
        }
    }

    fn parent_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.parent_hash,
            Self::Capella(bid) => &mut bid.header.parent_hash,
        }
    }

    fn prev_randao_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.prev_randao,
            Self::Capella(bid) => &mut bid.header.prev_randao,
        }
    }

    fn block_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.block_number,
            Self::Capella(bid) => &mut bid.header.block_number,
        }
    }

    fn timestamp_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.timestamp,
            Self::Capella(bid) => &mut bid.header.timestamp,
        }
    }

    fn withdrawals_root_mut(&mut self) -> Result<&mut Root, BlindedBlockProviderError> {
        match self {
            Self::Bellatrix(_) => Err(BlindedBlockProviderError::Custom(
                "withdrawals_root called on bellatrix bid".to_string(),
            )),
            Self::Capella(bid) => Ok(&mut bid.header.withdrawals_root),
        }
    }

    fn sign_builder_message(
        &mut self,
        signing_key: &SecretKey,
        context: &Context,
    ) -> Result<Signature, Error> {
        match self {
            Self::Bellatrix(message) => sign_builder_message(message, signing_key, context),
            Self::Capella(message) => sign_builder_message(message, signing_key, context),
        }
    }

    fn to_signed_bid(self, signature: Signature) -> SignedBuilderBid {
        match self {
            Self::Bellatrix(message) => {
                SignedBuilderBid::Bellatrix(SignedBuilderBidBellatrix { message, signature })
            }
            Self::Capella(message) => {
                SignedBuilderBid::Capella(SignedBuilderBidCapella { message, signature })
            }
        }
    }
}

pub struct TestingBuilder<E: EthSpec> {
    pub builder: MockBuilder<E>,
}

#[allow(unused)]
#[derive(Clone)]
pub struct MockBuilder<E: EthSpec> {
    el: ExecutionLayer<E>,
    spec: ChainSpec,
    context: Arc<Context>,
    val_registration_cache: Arc<RwLock<HashMap<BlsPublicKey, SignedValidatorRegistration>>>,
    builder_sk: SecretKey,
    operations: Arc<RwLock<Vec<Operation>>>,
    invalidate_signatures: Arc<RwLock<bool>>,
}

impl<E: EthSpec> MockBuilder<E> {
    pub fn new(el: ExecutionLayer<E>, spec: ChainSpec, context: Context) -> Self {
        let sk = SecretKey::random(&mut rand::thread_rng()).unwrap();
        Self {
            el,
            // Should keep spec and context consistent somehow
            spec,
            context: Arc::new(context),
            val_registration_cache: Arc::new(RwLock::new(HashMap::new())),
            builder_sk: sk,
            operations: Arc::new(RwLock::new(vec![])),
            invalidate_signatures: Arc::new(RwLock::new(false)),
        }
    }

    pub fn add_operation(&self, op: Operation) {
        // Insert operations at the front of the vec to make sure `apply_operations` applies them
        // in the order they are added.
        self.operations.write().insert(0, op);
    }

    pub fn invalid_signatures(&self) {
        *self.invalidate_signatures.write() = true;
    }

    pub fn valid_signatures(&mut self) {
        *self.invalidate_signatures.write() = false;
    }

    fn _apply_operations<B: BidStuff>(&self, bid: &mut B) -> Result<(), BlindedBlockProviderError> {
        let mut guard = self.operations.write();
        while let Some(op) = guard.pop() {
            op.apply(bid)?;
        }
        Ok(())
    }
}

#[allow(unused)]
pub fn from_ssz_rs<T: SimpleSerialize, U: Decode>(
    ssz_rs_data: &T,
) -> Result<U, BlindedBlockProviderError> {
    U::from_ssz_bytes(
        ssz_rs::serialize(ssz_rs_data)
            .map_err(convert_err)?
            .as_ref(),
    )
    .map_err(convert_err)
}

pub fn to_ssz_rs<T: Encode, U: SimpleSerialize>(
    ssz_data: &T,
) -> Result<U, BlindedBlockProviderError> {
    ssz_rs::deserialize::<U>(&ssz_data.as_ssz_bytes()).map_err(convert_err)
}

fn convert_err<E: Debug>(e: E) -> BlindedBlockProviderError {
    BlindedBlockProviderError::Custom(format!("{e:?}"))
}
