// src/main.rs
use ed25519_dalek::{
    Signature, Signer, Verifier, SigningKey, VerifyingKey,
    SECRET_KEY_LENGTH,
};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc}; 
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionProposal {
    pub transaction_id: Uuid,
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
pub enum P2PMessage {
    ProposeTransaction {
        proposal: TransactionProposal,
        sender_signature: String,
    },
    AcknowledgeAndCountersign {
        signed_transaction: SignedTransaction,
    },
    RejectTransaction {
        transaction_id: Uuid,
        reason: String,
    },
}

#[derive(Debug)]
pub struct User {
    pub id: String,
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub balance: i64,
    nonce: u64,
    known_peers: HashMap<String, VerifyingKey>,
}

impl User {
    pub fn new(id: String, initial_balance: i64) -> Self {
        let mut csprng = OsRng {};
        let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
        csprng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = VerifyingKey::from(&signing_key);

        println!(
            "User {} created. Public Key: {}",
            id,
            hex::encode(verifying_key.as_bytes())
        );
        User {
            id,
            signing_key,
            verifying_key,
            balance: initial_balance,
            nonce: 0,
            known_peers: HashMap::new(),
        }
    }

    pub fn add_known_peer(&mut self, peer_id: String, peer_verifying_key: VerifyingKey) {
        self.known_peers.insert(peer_id, peer_verifying_key);
    }

    fn get_peer_verifying_key(&self, peer_id: &str) -> Option<&VerifyingKey> {
        self.known_peers.get(peer_id)
    }

    fn serialize_for_text_message<T: Serialize>(data: &T) -> Result<String, serde_json::Error> {
        serde_json::to_string(data)
    }

    fn deserialize_from_text_message<'a, T: Deserialize<'a>>(text: &'a str) -> Result<T, serde_json::Error> {
        serde_json::from_str(text)
    }

    pub fn propose_transaction_text(
        &mut self,
        receiver_id: String,
        amount: u64,
    ) -> Result<String, String> {
        if self.balance < amount as i64 {
            return Err("Insufficient funds".to_string());
        }

        self.nonce += 1;
        let proposal = TransactionProposal { // THIS LINE NEEDS TransactionProposal DEFINITION
            transaction_id: Uuid::new_v4(),
            sender_id: self.id.clone(),
            receiver_id,
            amount,
            sender_nonce: self.nonce,
            timestamp: Utc::now(),
        };

        let proposal_bytes = serde_json::to_vec(&proposal).map_err(|e| e.to_string())?;
        let signature = self.signing_key.sign(&proposal_bytes);

        let message = P2PMessage::ProposeTransaction { // THIS LINE NEEDS P2PMessage DEFINITION
            proposal,
            sender_signature: hex::encode(signature.to_bytes()),
        };

        User::serialize_for_text_message(&message).map_err(|e| e.to_string())
    }

    pub fn receive_proposal_and_countersign_text(
        &mut self,
        message_text: &str,
        expected_amount: u64,
    ) -> Result<String, String> {
        let message: P2PMessage = User::deserialize_from_text_message(message_text) // THIS LINE
            .map_err(|e| format!("Deserialization error: {}", e))?;

        match message { // THIS LINE
            P2PMessage::ProposeTransaction { proposal, sender_signature } => { // THIS LINE
                let sender_vk = self.get_peer_verifying_key(&proposal.sender_id)
                    .ok_or_else(|| format!("Unknown sender public key for ID: {}", proposal.sender_id))?;

                let proposal_bytes = serde_json::to_vec(&proposal).map_err(|e| e.to_string())?;
                let signature_bytes = hex::decode(&sender_signature).map_err(|e| e.to_string())?;

                let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| "Invalid signature length for sender".to_string())?;
                let signature = Signature::from_bytes(&signature_array);

                sender_vk.verify(&proposal_bytes, &signature)
                    .map_err(|e| format!("Sender signature verification failed: {}", e))?;

                if proposal.amount != expected_amount {
                    let rejection = P2PMessage::RejectTransaction { // THIS LINE
                        transaction_id: proposal.transaction_id,
                        reason: format!(
                            "Amount mismatch. Proposed: {}, Expected: {}",
                            proposal.amount, expected_amount
                        ),
                    };
                    return User::serialize_for_text_message(&rejection).map_err(|e| e.to_string());
                }
                if proposal.receiver_id != self.id {
                     return Err(format!("Proposal not intended for this receiver. Expected: {}, Got: {}", self.id, proposal.receiver_id));
                }

                let receiver_signature_bytes = self.signing_key.sign(&proposal_bytes);
                let signed_transaction = SignedTransaction { // THIS LINE
                    proposal,
                    sender_signature,
                    receiver_signature: hex::encode(receiver_signature_bytes.to_bytes()),
                };

                self.balance += signed_transaction.proposal.amount as i64;
                println!(
                    "[Receiver {}] Countersigned. New balance: {}. TX_ID: {}",
                    self.id, self.balance, signed_transaction.proposal.transaction_id
                );

                let response_message = P2PMessage::AcknowledgeAndCountersign { // THIS LINE
                    signed_transaction,
                };
                User::serialize_for_text_message(&response_message).map_err(|e| e.to_string())
            }
            _ => Err("Invalid message type received. Expected ProposeTransaction.".to_string()),
        }
    }

    pub fn finalize_transaction_text(
        &mut self,
        message_text: &str,
    ) -> Result<SignedTransaction, String> { // THIS LINE
        let message: P2PMessage = User::deserialize_from_text_message(message_text) // THIS LINE
            .map_err(|e| format!("Deserialization error: {}", e))?;

        match message { // THIS LINE
            P2PMessage::AcknowledgeAndCountersign { signed_transaction } => { // THIS LINE
                if signed_transaction.proposal.sender_id != self.id {
                    return Err("Finalized transaction not initiated by me.".to_string());
                }

                let receiver_vk = self.get_peer_verifying_key(&signed_transaction.proposal.receiver_id)
                    .ok_or_else(|| format!("Unknown receiver public key for ID: {}", signed_transaction.proposal.receiver_id))?;

                let proposal_bytes = serde_json::to_vec(&signed_transaction.proposal).map_err(|e| e.to_string())?;

                let receiver_sig_bytes = hex::decode(&signed_transaction.receiver_signature).map_err(|e| e.to_string())?;
                let receiver_signature_array: [u8; 64] = receiver_sig_bytes.try_into().map_err(|_| "Invalid signature length for receiver".to_string())?;
                let receiver_signature = Signature::from_bytes(&receiver_signature_array);

                receiver_vk.verify(&proposal_bytes, &receiver_signature)
                    .map_err(|e| format!("Receiver signature verification failed: {}", e))?;

                let my_original_sig_bytes = hex::decode(&signed_transaction.sender_signature).map_err(|e| e.to_string())?;
                let my_original_signature_array: [u8; 64] = my_original_sig_bytes.try_into().map_err(|_| "Invalid signature length for my original sig".to_string())?;
                let my_original_signature = Signature::from_bytes(&my_original_signature_array);

                self.verifying_key.verify(&proposal_bytes, &my_original_signature)
                     .map_err(|e| format!("My own original signature verification failed: {}", e))?;

                self.balance -= signed_transaction.proposal.amount as i64;
                println!(
                    "[Payer {}] Transaction finalized. New balance: {}. TX_ID: {}",
                    self.id, self.balance, signed_transaction.proposal.transaction_id
                );
                Ok(signed_transaction)
            }
            P2PMessage::RejectTransaction { transaction_id, reason } => { // THIS LINE
                Err(format!("Transaction {} rejected by peer: {}", transaction_id, reason))
            }
            _ => Err("Invalid message type received. Expected AcknowledgeAndCountersign or RejectTransaction.".to_string()),
        }
    }
}

#[derive(Default)]
pub struct OrganizationService {
    user_public_keys: HashMap<String, VerifyingKey>,
    transaction_ledger: Vec<SignedTransaction>, // THIS LINE
    user_balances_on_org: HashMap<String, i64>,
}

impl OrganizationService {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register_user(&mut self, user_id: String, verifying_key: VerifyingKey, initial_balance: i64) {
        println!("[Org] Registered user: {}", user_id);
        self.user_public_keys.insert(user_id.clone(), verifying_key);
        self.user_balances_on_org.insert(user_id, initial_balance);
    }

    pub fn submit_transaction_for_syncing(&mut self, signed_tx: &SignedTransaction) -> Result<(), String> { // THIS LINE
        println!("[Org] Received transaction for syncing: TX_ID {}", signed_tx.proposal.transaction_id);
        let sender_vk = self.user_public_keys.get(&signed_tx.proposal.sender_id)
            .ok_or_else(|| format!("Sender {} not registered with organization", signed_tx.proposal.sender_id))?;
        let receiver_vk = self.user_public_keys.get(&signed_tx.proposal.receiver_id)
            .ok_or_else(|| format!("Receiver {} not registered with organization", signed_tx.proposal.receiver_id))?;

        let proposal_bytes = serde_json::to_vec(&signed_tx.proposal).map_err(|e| e.to_string())?;

        let sender_sig_bytes = hex::decode(&signed_tx.sender_signature).map_err(|e| e.to_string())?;
        let sender_signature_array: [u8; 64] = sender_sig_bytes.try_into().map_err(|_| "Invalid sender signature length for org check".to_string())?;
        let sender_signature = Signature::from_bytes(&sender_signature_array);
        sender_vk.verify(&proposal_bytes, &sender_signature)
            .map_err(|e| format!("Org: Sender signature invalid: {}", e))?;

        let receiver_sig_bytes = hex::decode(&signed_tx.receiver_signature).map_err(|e| e.to_string())?;
        let receiver_signature_array: [u8; 64] = receiver_sig_bytes.try_into().map_err(|_| "Invalid receiver signature length for org check".to_string())?;
        let receiver_signature = Signature::from_bytes(&receiver_signature_array);
        receiver_vk.verify(&proposal_bytes, &receiver_signature)
            .map_err(|e| format!("Org: Receiver signature invalid: {}", e))?;

        if self.transaction_ledger.iter().any(|tx| tx.proposal.transaction_id == signed_tx.proposal.transaction_id) {
             return Err(format!("[Org] Transaction {} already synced.", signed_tx.proposal.transaction_id));
        }

        let amount = signed_tx.proposal.amount as i64;
        *self.user_balances_on_org.entry(signed_tx.proposal.sender_id.clone()).or_insert(0) -= amount;
        *self.user_balances_on_org.entry(signed_tx.proposal.receiver_id.clone()).or_insert(0) += amount;

        self.transaction_ledger.push(signed_tx.clone());
        println!("[Org] Transaction TX_ID {} successfully synced and recorded.", signed_tx.proposal.transaction_id);
        println!("[Org] Balances: Sender ({}): {}, Receiver ({}): {}",
            signed_tx.proposal.sender_id, self.user_balances_on_org[&signed_tx.proposal.sender_id],
            signed_tx.proposal.receiver_id, self.user_balances_on_org[&signed_tx.proposal.receiver_id]
        );
        Ok(())
    }

    pub fn get_user_public_key(&self, user_id: &str) -> Option<VerifyingKey> {
        self.user_public_keys.get(user_id).cloned()
    }

     pub fn print_ledger(&self) {
        println!("\n--- Organization Transaction Ledger ---");
        for tx in &self.transaction_ledger {
            println!(
                "  TX_ID: {}, From: {}, To: {}, Amount: {}, Sender Nonce: {}, Timestamp: {}",
                tx.proposal.transaction_id,
                tx.proposal.sender_id,
                tx.proposal.receiver_id,
                tx.proposal.amount,
                tx.proposal.sender_nonce,
                tx.proposal.timestamp
            );
        }
        println!("--- End Ledger ---");
    }
}

fn main() {
    let mut org_service = OrganizationService::new();

    let mut alice = User::new("alice".to_string(), 1000);
    let mut bob = User::new("bob".to_string(), 500);

    org_service.register_user("alice".to_string(), alice.verifying_key, alice.balance);
    org_service.register_user("bob".to_string(), bob.verifying_key, bob.balance);

    alice.add_known_peer("bob".to_string(), org_service.get_user_public_key("bob").unwrap());
    bob.add_known_peer("alice".to_string(), org_service.get_user_public_key("alice").unwrap());

    println!("\n--- Initial Balances ---");
    println!("Alice: {}, Bob: {}", alice.balance, bob.balance);

    // --- Transaction 1: Alice pays Bob 50 ---
    println!("\n--- Transaction 1: Alice pays Bob 50 (Off-chain) ---");
    let amount_to_send = 50;
    let proposal_text = alice.propose_transaction_text("bob".to_string(), amount_to_send).unwrap();
    println!("[Alice->Bob] Sent proposal (as text): {}", proposal_text);

    let countersigned_text = bob.receive_proposal_and_countersign_text(&proposal_text, amount_to_send).unwrap();
    println!("[Bob->Alice] Sent countersigned ack (as text): {}", countersigned_text);

    let finalized_tx1 = alice.finalize_transaction_text(&countersigned_text).unwrap();
    println!("[Alice] Transaction 1 complete locally.");

    println!("\n--- Balances after Off-chain TX 1 (Local View) ---");
    println!("Alice: {}, Bob: {}", alice.balance, bob.balance);

    println!("\n--- Syncing Transaction 1 with Organization ---");
    if let Err(e) = org_service.submit_transaction_for_syncing(&finalized_tx1) {
        eprintln!("Error syncing TX1: {}", e);
    }

    // --- Transaction 2: Bob pays Alice 20 ---
    println!("\n--- Transaction 2: Bob pays Alice 20 (Off-chain) ---");
    let amount_to_send_2 = 20;
    let proposal_text_2 = bob.propose_transaction_text("alice".to_string(), amount_to_send_2).unwrap();
    println!("[Bob->Alice] Sent proposal (as text): {}", proposal_text_2);

    let countersigned_text_2 = alice.receive_proposal_and_countersign_text(&proposal_text_2, amount_to_send_2).unwrap();
    println!("[Alice->Bob] Sent countersigned ack (as text): {}", countersigned_text_2);

    let finalized_tx2 = bob.finalize_transaction_text(&countersigned_text_2).unwrap();
    println!("[Bob] Transaction 2 complete locally.");

    println!("\n--- Balances after Off-chain TX 2 (Local View) ---");
    println!("Alice: {}, Bob: {}", alice.balance, bob.balance);

    println!("\n--- Syncing Transaction 2 with Organization ---");
     if let Err(e) = org_service.submit_transaction_for_syncing(&finalized_tx2) {
        eprintln!("Error syncing TX2: {}", e);
    }

    println!("\n--- Attempting to re-sync Transaction 1 (Fraud Attempt by Alice) ---");
    if let Err(e) = org_service.submit_transaction_for_syncing(&finalized_tx1) {
        eprintln!("[Org] Correctly rejected re-sync of TX1: {}", e);
    } else {
        println!("[Org] ERROR: Allowed re-syncing of TX1!");
    }

    println!("\n--- Transaction 3: Alice pays Bob 100, Bob expects 10 (Mismatch) ---");
    let amount_to_send_3 = 100;
    let bob_expected_amount_3 = 10;
    let proposal_text_3 = alice.propose_transaction_text("bob".to_string(), amount_to_send_3).unwrap();
    println!("[Alice->Bob] Sent proposal (as text): {}", proposal_text_3);

    match bob.receive_proposal_and_countersign_text(&proposal_text_3, bob_expected_amount_3) {
        Ok(_) => println!("[Bob] ERROR: Transaction should have been rejected due to amount mismatch!"),
        Err(rejection_msg_text) => {
            println!("[Bob->Alice] Sent rejection (as text): {}", rejection_msg_text);
            match alice.finalize_transaction_text(&rejection_msg_text) {
                Ok(_) => println!("[Alice] ERROR: Finalized a rejected transaction!"),
                Err(rejection_reason) => {
                    println!("[Alice] Received rejection: {}", rejection_reason);
                }
            }
        }
    }

    println!("\n--- Balances after failed TX3 (Local View) ---");
    println!("Alice: {}, Bob: {}", alice.balance, bob.balance);

    org_service.print_ledger();

    println!("\n--- Final Organization Balances ---");
    println!("Alice (Org): {}", org_service.user_balances_on_org["alice"]);
    println!("Bob (Org): {}", org_service.user_balances_on_org["bob"]);
}
