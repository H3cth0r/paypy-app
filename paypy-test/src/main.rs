// src/main.rs
use ed25519_dalek::{
    Signature, Signer, Verifier, SigningKey, VerifyingKey,
    SECRET_KEY_LENGTH,
};


use rand::{ rngs::OsRng, RngCore };
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use chrono::{DateTime, Utc}
use uuid::Uuid;

//Data Structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionProposal {
    pub transaction_id: Uuid;
    pub sender_id: String,
    pub receiver_id: String,
    pub amount: u64,
    pub sender_nonce: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedTransaction {
    pub proposal: TransactionProposal,
    pub sender_signature: String,
    pub receiver_signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum P2Message {
    ProposeTransaction {
        proposal: TransactionProposal,
        sender_signature: String,
    },
    AcknowledgeAndCountersign {
        signed_transaction: SignedTransaction,
    },
    RejectTransaction {
        transaction_id:  Uuid,
        reason: String,
    },
}
