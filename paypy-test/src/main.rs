// src/main.rs

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;

// Core domain models

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub blockchain_key: String, // Provided by the organization to verify membership
    pub balance: u64,
    // We'll store the signing key securely in memory only (not serialized)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub sender_id: String,
    pub receiver_id: String,
    pub amount: u64,
    pub timestamp: DateTime<Utc>,
    pub sender_balance_signature: String,
    pub receiver_balance_signature: String,
    pub status: TransactionStatus,
    pub memo: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Proposed,
    AmountConfirmed,
    Completed,
    Synced,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub sender_id: String,
    pub receiver_id: String,
    pub content: String, // Encrypted content
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationVerification {
    pub user_id: String,
    pub last_sync_timestamp: DateTime<Utc>,
    pub organization_signature: String,
}

// Main wallet struct to handle both sending and receiving
pub struct Wallet {
    user: User,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    pending_transactions: HashMap<String, Transaction>,
    completed_transactions: Vec<Transaction>,
    organization_verification: Option<OrganizationVerification>,
    communication_keys: HashMap<String, Vec<u8>>, // User ID -> Shared secret key
}

impl Wallet {
    pub fn new(username: String, blockchain_key: String, initial_balance: u64) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        
        let user_id = Uuid::new_v4().to_string();
        
        Self {
            user: User {
                id: user_id,
                username,
                blockchain_key,
                balance: initial_balance,
            },
            signing_key,
            verifying_key,
            pending_transactions: HashMap::new(),
            completed_transactions: Vec::new(),
            organization_verification: None,
            communication_keys: HashMap::new(),
        }
    }
    
    // Get public key bytes that can be shared with counterparties
    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
    
    // Establish encrypted communication with another user
    pub fn establish_secure_channel(&mut self, counterparty_id: &str, shared_secret: Vec<u8>) {
        self.communication_keys.insert(counterparty_id.to_string(), shared_secret);
    }
    
    // Send encrypted message to another user
    pub fn send_message(&self, receiver_id: &str, content: &str) -> Result<Message, String> {
        let shared_key = self.communication_keys.get(receiver_id)
            .ok_or("No secure channel established with receiver")?;
        
        // Create a random nonce
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt message
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        let ciphertext = cipher.encrypt(nonce, content.as_bytes())
            .map_err(|_| "Encryption failed")?;
        
        // Combine nonce and ciphertext and encode as base64
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        let encoded = general_purpose::STANDARD.encode(combined);
        
        Ok(Message {
            sender_id: self.user.id.clone(),
            receiver_id: receiver_id.to_string(),
            content: encoded,
            timestamp: Utc::now(),
        })
    }
    
    // Decrypt and read received message
    pub fn read_message(&self, message: &Message) -> Result<String, String> {
        if message.receiver_id != self.user.id {
            return Err("Message not intended for this user".to_string());
        }
        
        let shared_key = self.communication_keys.get(&message.sender_id)
            .ok_or("No secure channel established with sender")?;
        
        // Decode base64
        let decoded = general_purpose::STANDARD.decode(&message.content)
            .map_err(|_| "Failed to decode message")?;
        
        if decoded.len() < 12 {
            return Err("Invalid message format".to_string());
        }
        
        // Split into nonce and ciphertext
        let nonce_bytes = &decoded[..12];
        let ciphertext = &decoded[12..];
        
        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Key::from_slice(shared_key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Decrypt message
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed")?;
        
        String::from_utf8(plaintext)
            .map_err(|_| "Invalid UTF-8 in decrypted message".to_string())
    }
    
    // Initiate a new transaction proposal
    pub fn propose_transaction(&mut self, receiver_id: &str, amount: u64) -> Result<Transaction, String> {
        if amount > self.user.balance {
            return Err("Insufficient funds".to_string());
        }
        
        let transaction = Transaction {
            id: Uuid::new_v4().to_string(),
            sender_id: self.user.id.clone(),
            receiver_id: receiver_id.to_string(),
            amount,
            timestamp: Utc::now(),
            sender_balance_signature: "".to_string(),
            receiver_balance_signature: "".to_string(),
            status: TransactionStatus::Proposed,
            memo: None,
        };
        
        self.pending_transactions.insert(transaction.id.clone(), transaction.clone());
        Ok(transaction)
    }
    
    // Confirm amount as receiver
    pub fn confirm_transaction_amount(&mut self, transaction_id: &str) -> Result<Transaction, String> {
        let transaction = self.pending_transactions.get_mut(transaction_id)
            .ok_or("Transaction not found")?;
        
        if transaction.receiver_id != self.user.id {
            return Err("User is not the receiver for this transaction".to_string());
        }
        
        transaction.status = TransactionStatus::AmountConfirmed;
        Ok(transaction.clone())
    }
    
    // Sign the sender balance after transaction
    pub fn sign_sender_balance(&mut self, transaction_id: &str) -> Result<Transaction, String> {
        let transaction = self.pending_transactions.get_mut(transaction_id)
            .ok_or("Transaction not found")?;
        
        if transaction.sender_id != self.user.id {
            return Err("User is not the sender for this transaction".to_string());
        }
        
        if transaction.status != TransactionStatus::AmountConfirmed {
            return Err("Transaction amount not yet confirmed by receiver".to_string());
        }
        
        // Create a new updated balance
        let new_balance = self.user.balance - transaction.amount;
        
        // Sign the new balance
        let balance_to_sign = format!("{}:{}", self.user.id, new_balance);
        let signature = self.signing_key.sign(balance_to_sign.as_bytes());
        
        transaction.sender_balance_signature = general_purpose::STANDARD.encode(signature.to_bytes());
        
        // Update local balance
        self.user.balance = new_balance;
        
        Ok(transaction.clone())
    }
    
    // Sign the receiver balance after transaction
    pub fn sign_receiver_balance(&mut self, transaction_id: &str) -> Result<Transaction, String> {
        let transaction = self.pending_transactions.get_mut(transaction_id)
            .ok_or("Transaction not found")?;
        
        if transaction.receiver_id != self.user.id {
            return Err("User is not the receiver for this transaction".to_string());
        }
        
        if transaction.sender_balance_signature.is_empty() {
            return Err("Sender has not yet signed their balance".to_string());
        }
        
        // Create a new updated balance
        let new_balance = self.user.balance + transaction.amount;
        
        // Sign the new balance
        let balance_to_sign = format!("{}:{}", self.user.id, new_balance);
        let signature = self.signing_key.sign(balance_to_sign.as_bytes());
        
        transaction.receiver_balance_signature = general_purpose::STANDARD.encode(signature.to_bytes());
        transaction.status = TransactionStatus::Completed;
        
        // Update local balance
        self.user.balance = new_balance;
        
        // Move from pending to completed
        let completed_tx = transaction.clone();
        self.pending_transactions.remove(transaction_id);
        self.completed_transactions.push(completed_tx.clone());
        
        Ok(completed_tx)
    }
    
    // Verify a transaction (can be done by any party)
    pub fn verify_transaction(&self, transaction: &Transaction, 
                               sender_pubkey: &VerifyingKey, 
                               receiver_pubkey: &VerifyingKey) -> Result<bool, String> {
        // Verify sender signature
        let sender_balance = self.user.balance - transaction.amount;
        let sender_data = format!("{}:{}", transaction.sender_id, sender_balance);
        let sender_sig_bytes = general_purpose::STANDARD.decode(&transaction.sender_balance_signature)
            .map_err(|_| "Invalid sender signature encoding")?;
        let sender_signature = Signature::from_bytes(&sender_sig_bytes)
            .map_err(|_| "Invalid sender signature format")?;
        
        if sender_pubkey.verify(sender_data.as_bytes(), &sender_signature).is_err() {
            return Ok(false);
        }
        
        // Verify receiver signature
        let receiver_balance = self.user.balance + transaction.amount;
        let receiver_data = format!("{}:{}", transaction.receiver_id, receiver_balance);
        let receiver_sig_bytes = general_purpose::STANDARD.decode(&transaction.receiver_balance_signature)
            .map_err(|_| "Invalid receiver signature encoding")?;
        let receiver_signature = Signature::from_bytes(&receiver_sig_bytes)
            .map_err(|_| "Invalid receiver signature format")?;
        
        if receiver_pubkey.verify(receiver_data.as_bytes(), &receiver_signature).is_err() {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    // Sync with the organization/blockchain
    pub fn sync_with_organization(&mut self, org_service: &OrganizationService) -> Result<(), String> {
        // Submit all completed transactions since last sync
        for transaction in &self.completed_transactions {
            if transaction.status == TransactionStatus::Completed {
                // In a real implementation, this would involve network calls
                org_service.submit_transaction(transaction)?;
            }
        }
        
        // Get latest organization verification
        let verification = org_service.verify_user(&self.user.id, &self.user.blockchain_key)?;
        self.organization_verification = Some(verification);
        
        // Mark transactions as synced
        for transaction in &mut self.completed_transactions {
            if transaction.status == TransactionStatus::Completed {
                transaction.status = TransactionStatus::Synced;
            }
        }
        
        Ok(())
    }
}

// Mock organization/blockchain service
pub struct OrganizationService {
    verified_users: Arc<Mutex<HashMap<String, User>>>,
    transactions: Arc<Mutex<Vec<Transaction>>>,
    org_signing_key: SigningKey,
}

impl OrganizationService {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        
        Self {
            verified_users: Arc::new(Mutex::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(Vec::new())),
            org_signing_key: signing_key,
        }
    }
    
    pub fn register_user(&self, user: User, verifying_key_bytes: &[u8]) -> Result<String, String> {
        let mut users = self.verified_users.lock().unwrap();
        
        // In a real implementation, this would involve more validation
        users.insert(user.id.clone(), user.clone());
        
        // Generate and return a blockchain key
        Ok(Uuid::new_v4().to_string())
    }
    
    pub fn verify_user(&self, user_id: &str, blockchain_key: &str) -> Result<OrganizationVerification, String> {
        let users = self.verified_users.lock().unwrap();
        
        // Check if user exists and blockchain key matches
        let user = users.get(user_id)
            .ok_or("User not found")?;
        
        if user.blockchain_key != blockchain_key {
            return Err("Invalid blockchain key".to_string());
        }
        
        // Create verification
        let verification_data = format!("{}:{}", user_id, Utc::now());
        let signature = self.org_signing_key.sign(verification_data.as_bytes());
        
        Ok(OrganizationVerification {
            user_id: user_id.to_string(),
            last_sync_timestamp: Utc::now(),
            organization_signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        })
    }
    
    pub fn submit_transaction(&self, transaction: &Transaction) -> Result<(), String> {
        let mut transactions = self.transactions.lock().unwrap();
        transactions.push(transaction.clone());
        Ok(())
    }
}

// Example of how to use the system
fn main() {
    // Create an organization service
    let org_service = OrganizationService::new();
    
    // Create Alice's wallet
    let mut alice_wallet = Wallet::new(
        "Alice".to_string(),
        "blockchain-key-placeholder".to_string(),
        1000
    );
    
    // Register Alice with the organization
    let alice_blockchain_key = org_service.register_user(
        alice_wallet.user.clone(),
        &alice_wallet.get_public_key_bytes()
    ).unwrap();
    alice_wallet.user.blockchain_key = alice_blockchain_key;
    
    // Create Bob's wallet
    let mut bob_wallet = Wallet::new(
        "Bob".to_string(),
        "blockchain-key-placeholder".to_string(),
        500
    );
    
    // Register Bob with the organization
    let bob_blockchain_key = org_service.register_user(
        bob_wallet.user.clone(),
        &bob_wallet.get_public_key_bytes()
    ).unwrap();
    bob_wallet.user.blockchain_key = bob_blockchain_key;
    
    // Establish secure communication channels (in a real app, this would involve key exchange)
    let shared_secret = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    alice_wallet.establish_secure_channel(&bob_wallet.user.id, shared_secret.clone());
    bob_wallet.establish_secure_channel(&alice_wallet.user.id, shared_secret);
    
    // Alice sends a message to Bob
    let message = alice_wallet.send_message(&bob_wallet.user.id, "Hi Bob, I want to send you 50 tokens").unwrap();
    
    // Bob reads the message
    let content = bob_wallet.read_message(&message).unwrap();
    println!("Bob received: {}", content);
    
    // Alice proposes a transaction
    let transaction = alice_wallet.propose_transaction(&bob_wallet.user.id, 50).unwrap();
    
    // Bob confirms the amount
    let mut transaction = bob_wallet.confirm_transaction_amount(&transaction.id).unwrap();
    
    // Alice signs her new balance
    transaction = alice_wallet.sign_sender_balance(&transaction.id).unwrap();
    
    // Bob signs his new balance
    transaction = bob_wallet.sign_receiver_balance(&transaction.id).unwrap();
    
    println!("Transaction completed successfully!");
    println!("Alice's new balance: {}", alice_wallet.user.balance);
    println!("Bob's new balance: {}", bob_wallet.user.balance);
    
    // Sync with organization/blockchain
    alice_wallet.sync_with_organization(&org_service).unwrap();
    bob_wallet.sync_with_organization(&org_service).unwrap();
    
    println!("Wallets synced with the organization successfully!");
}
