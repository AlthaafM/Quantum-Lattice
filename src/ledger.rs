use serde::{Serialize, Deserialize};
use chrono::Utc;
use sha3::{Digest, Sha3_256};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: Vec<u8>,      
    pub receiver: Vec<u8>,    
    pub amount: u64,          
    pub signature: Vec<u8>,   
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_block_hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub timestamp: i64,
    pub block_height: u64,
    pub miner: Vec<u8>,
    // Added in Phase 5 for real proof-of-work mining.
    pub nonce: u64,
}

impl BlockHeader {
    /// The actual mining puzzle. Deliberately excludes timestamp — if it
    /// were included, the miner and node would need to agree on an exact
    /// clock value just to reproduce the same hash, which serves no purpose
    /// here. Covers only the fields fixed at template-issue time plus the
    /// nonce the miner is searching over.
    ///
    /// IMPORTANT: src/bin/miner.rs has its OWN independent copy of this
    /// exact same logic (it doesn't link against this module). If you
    /// change this function, you must change the miner's copy identically,
    /// or mining will silently never succeed.
    pub fn calculate_pow_hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.previous_block_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.miner);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Transaction {
    pub fn new(sender: Vec<u8>, receiver: Vec<u8>, amount: u64, signature: Vec<u8>) -> Self {
        Self {
            sender,
            receiver,
            amount,
            signature,
            timestamp: Utc::now().timestamp(),
        }
    }
}

impl Block {
    // Computes an absolute SHA3-256 hash of the entire block structure for absolute immutability
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        let serialized_data = bincode::serialize(self).expect("[CRITICAL] Block hashing serialization failure");
        hasher.update(&serialized_data);
        hasher.finalize().to_vec()
    }
}
