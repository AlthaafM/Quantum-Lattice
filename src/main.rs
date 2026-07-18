mod ledger;
mod network;
mod consensus;
mod wallet;
mod users;
mod email;
mod ratelimit;

use ledger::{Block, BlockHeader, Transaction};
use network::P2PNode;
use consensus::{ConsensusEngine, ConsensusState, STATE_KEY};
use rocksdb::{DB, Options};
use bincode::{serialize, deserialize};
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use sha3::{Digest, Sha3_256};

/// Generates (once) or loads a persistent admin token per node. Not a
/// cryptographic-grade RNG — it's a hash of current time + process ID, which
/// is fine for a local single-operator dev token, not something to rely on
/// for a production secret in a hostile environment.
fn get_or_create_admin_token(key_prefix: &str) -> String {
    let path = format!("{}_admin_token.txt", key_prefix);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seed = format!("{}-{}", nanos, std::process::id());
    let mut hasher = Sha3_256::new();
    hasher.update(seed.as_bytes());
    let token = hex::encode(hasher.finalize());

    std::fs::write(&path, &token).expect("Failed to write admin token file");
    token
}

#[tokio::main]
async fn main() {
    // Loads secrets.env if present (SMTP credentials for email
    // verification). Silently continues if missing — email verification
    // simply won't work until it's added, but nothing else depends on it.
    dotenvy::from_filename("secrets.env").ok();

    println!("=== QUANTUM-LATTICE (QL) SOVEREIGN POST-QUANTUM ENGINE BOOTING ===");
    println!("[INFO] Incorporated by FuturisticAI");

    let args: Vec<String> = env::args().collect();
    let node_mode = if args.len() > 1 { &args[1] } else { "node1" };

    let (p2p_port, rpc_port, admin_port, db_path, key_prefix, mut peers) = if node_mode == "node2" {
        (9033, 9034, 19034, "./ql_db_node2", "operational_vault_b", vec!["127.0.0.1:8033".to_string()])
    } else {
        (8033, 8034, 18034, "./ql_db_node1", "master_vault_a", vec!["127.0.0.1:9033".to_string()])
    };
    // Optional, purely additive: real external peers (e.g. someone else's
    // independently-run node) can be added without touching the hardcoded
    // defaults above at all, via a comma-separated env var:
    //   QL_EXTRA_PEERS=203.0.113.5:8033,198.51.100.9:8033
    // Existing behavior (node1 <-> node2 on localhost) is completely
    // unaffected either way.
    if let Ok(extra) = std::env::var("QL_EXTRA_PEERS") {
        for p in extra.split(',') {
            let p = p.trim();
            if !p.is_empty() {
                println!("[CONFIG] Adding external peer from QL_EXTRA_PEERS: {}", p);
                peers.push(p.to_string());
            }
        }
    }

    println!(
        "[CONFIG] Active profile: {} | DB: {} | Admin(loopback): {}",
        node_mode.to_uppercase(),
        db_path,
        admin_port
    );

    println!("[INIT] Unlocking vault keys — you'll be prompted for each vault's password.");
    let vault_a_seed = wallet::unlock_or_create_vault("master_vault_a");
    let vault_b_seed = wallet::unlock_or_create_vault("operational_vault_b");
    let vault_a_seed = Arc::new(vault_a_seed);
    let vault_b_seed = Arc::new(vault_b_seed);

    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open(&opts, db_path).expect("Failed to open database");
    println!("[SUCCESS] RocksDB locked to: {}", db_path);

    let vault_a_bytes = std::fs::read("master_vault_a_public.key").expect("vault A key missing");
    let vault_b_bytes = std::fs::read("operational_vault_b_public.key").expect("vault B key missing");

    // ---- THE CORE FIX: load real chain state if it exists, only run genesis once ----
    let engine = match db.get(STATE_KEY).unwrap() {
        Some(bytes) => {
            let state: ConsensusState = deserialize(&bytes).expect("Corrupt consensus state");
            ConsensusEngine::from_state(state)
        }
        None => {
            let engine = ConsensusEngine::genesis(vault_a_bytes.clone(), vault_b_bytes.clone());

            // FIXED, not chrono::Utc::now(). Every node must independently
            // compute a BYTE-IDENTICAL genesis block, or their chains can
            // never link — a real-time timestamp here was the actual bug
            // behind "chains have diverged" on first sync.
            const GENESIS_TIMESTAMP: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z, arbitrary fixed epoch

            let header = BlockHeader {
                version: 1,
                previous_block_hash: vec![0; 32],
                merkle_root: vec![0; 32],
                timestamp: GENESIS_TIMESTAMP,
                block_height: 0,
                miner: vec![], // genesis has no miner — nothing was mined
                nonce: 0,
            };
            let genesis_block = Block { header, transactions: vec![] };
            let genesis_hash = genesis_block.calculate_hash();
            println!("[CONSENSUS] Genesis Block Hash: {}", hex::encode(&genesis_hash));

            db.put(b"block_0", serialize(&genesis_block).unwrap()).unwrap();
            db.put(STATE_KEY, serialize(&engine.state).unwrap()).unwrap();
            engine
        }
    };

    println!(
        "[CONSENSUS] Height: {} | Supply: {} QL",
        engine.state.chain_height,
        engine.state.total_minted_supply / consensus::COIN
    );

    let engine = Arc::new(Mutex::new(engine));
    let mempool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
    let rate_limiter = Arc::new(ratelimit::RateLimiter::new());
    let db = Arc::new(db);
    let peer_activity: network::PeerActivity = Arc::new(Mutex::new(std::collections::HashMap::new()));

    let admin_token = get_or_create_admin_token(key_prefix);
    println!(
        "[ADMIN] Dashboard URL: http://127.0.0.1:{}/?token={}",
        admin_port, admin_token
    );
    println!(
        "[ADMIN] For the combined Master view showing BOTH nodes, add the other node's token: http://127.0.0.1:{}/?token={}&peer_token=OTHER_NODE_TOKEN",
        admin_port, admin_token
    );

    let p2p_node = P2PNode::new(p2p_port, rpc_port);
    p2p_node
        .start_p2p_server(engine.clone(), db.clone(), peers.clone(), peer_activity.clone())
        .await
        .expect("P2P server failed");
    p2p_node
        .start_rpc_server(db_path.to_string(), engine.clone(), mempool.clone(), db.clone(), peers.clone(), rate_limiter.clone())
        .await
        .expect("RPC server failed");
    p2p_node
        .start_admin_server(admin_port, engine.clone(), vault_a_bytes.clone(), vault_b_bytes.clone(), admin_token, db.clone(), mempool.clone(), vault_a_seed.clone(), vault_b_seed.clone(), peer_activity.clone())
        .await
        .expect("Admin server failed");

    // Periodic catch-up — without this, a node only ever checks for missed
    // blocks once at startup. If a peer was briefly unreachable at boot, or
    // simply joins the network later, there was previously no automatic way
    // to recover without a manual restart. Checking periodically (every 60s)
    // means every node stays genuinely current on its own going forward.
    println!("[STARTUP] Checking peers for any blocks we missed while offline...");
    {
        let engine_for_catchup = engine.clone();
        let db_for_catchup = db.clone();
        let peers_for_catchup = peers.clone();
        tokio::spawn(async move {
            loop {
                P2PNode::catch_up(engine_for_catchup.clone(), db_for_catchup.clone(), peers_for_catchup.clone()).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    println!(
        "\n[NODE ONLINE] P2P: {} | Public RPC: {} | Admin(loopback only): {}",
        p2p_port, rpc_port, admin_port
    );

    // ---- Test transaction ----
    // Still queues a real signed transfer so there's something for an
    // external miner to include — but nothing gets mined automatically
    // anymore. A block only gets produced when a miner actually submits
    // valid proof-of-work via /api/mining/submit (see network.rs and
    // src/bin/miner.rs).
    if node_mode != "node2" {
        let test_amount: u64 = 1 * consensus::COIN;
        let mut message = Vec::new();
        message.extend_from_slice(&vault_a_bytes);
        message.extend_from_slice(&vault_b_bytes);
        message.extend_from_slice(&test_amount.to_le_bytes());
        let signature = wallet::sign_with_seed_bytes(&vault_a_seed, &message);

        let test_tx = Transaction::new(vault_a_bytes.clone(), vault_b_bytes.clone(), test_amount, signature);
        mempool.lock().await.push(test_tx);
        println!("[TEST] Queued a signed 1 QL transfer (Vault A -> Vault B) into the mempool.");
    }

    println!("[MINING] Waiting for a miner to submit proof-of-work — run: cargo run --bin miner -- 127.0.0.1:{}", rpc_port);

    // Everything from here runs in spawned background tasks (P2P, RPC,
    // admin). This just keeps the process alive.
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
