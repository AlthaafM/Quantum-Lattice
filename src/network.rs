use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use rocksdb::DB;
use crate::consensus::{ConsensusEngine, COIN, STATE_KEY, meets_difficulty, RETARGET_INTERVAL};
use crate::ledger::{Block, BlockHeader, Transaction};
use crate::users;
use crate::email;
use crate::ratelimit::RateLimiter;
use crate::wallet::sign_with_seed_bytes;

/// Tracks the last time we successfully received ANY message from a given
/// peer IP over the P2P port — real, direct evidence of who's genuinely
/// connecting and participating, independent of whatever's in our own
/// configured peer list (which only reflects peers WE reach out to, not
/// who reaches out to us).
pub type PeerActivity = Arc<Mutex<HashMap<String, i64>>>;

#[derive(Serialize, Deserialize)]
pub enum P2PMessage {
    NewBlock(Block),
    RequestHeight,
    HeightResponse(u64),
    RequestBlocks(u64),
    BlocksResponse(Vec<Block>),
}

pub struct P2PNode {
    pub p2p_port: u16,
    pub rpc_port: u16,
}

fn extract_query_param(request_line: &str, key: &str) -> Option<String> {
    let path_part = request_line.split_whitespace().nth(1)?;
    let query = path_part.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next()?;
        let v = kv.next().unwrap_or("");
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let value_start = after_colon.strip_prefix('"')?;

    let mut result = String::new();
    let mut chars = value_start.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some(other) => { result.push('\\'); result.push(other); }
                None => break,
            }
        } else if c == '"' {
            return Some(result);
        } else {
            result.push(c);
        }
    }
    None
}

fn extract_json_number(body: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let end = after_colon.find(|c: char| c == ',' || c == '}').unwrap_or(after_colon.len());
    after_colon[..end].trim().parse::<u64>().ok()
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn read_http_request(socket: &mut TcpStream) -> String {
    let read_future = async {
        let mut data: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];

        loop {
            match socket.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&chunk[..n]);
                    if let Some(header_end) = find_header_end(&data) {
                        let headers = String::from_utf8_lossy(&data[..header_end]);
                        let content_length = headers
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);

                        if data.len() - header_end >= content_length {
                            break;
                        }
                    } else if data.len() > 65536 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        data
    };

    match tokio::time::timeout(std::time::Duration::from_secs(15), read_future).await {
        Ok(data) => String::from_utf8_lossy(&data).to_string(),
        Err(_) => String::new(),
    }
}

impl P2PNode {
    pub fn new(p2p_port: u16, rpc_port: u16) -> Self {
        Self { p2p_port, rpc_port }
    }

    async fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
        let len = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(payload).await
    }

    async fn read_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "claimed frame size exceeds the maximum allowed",
            ));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    pub async fn broadcast_block(peers: Vec<String>, block: Block) {
        let msg = P2PMessage::NewBlock(block);
        let payload = match serialize(&msg) {
            Ok(p) => p,
            Err(_) => return,
        };
        for peer in peers {
            let payload = payload.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = TcpStream::connect(&peer).await {
                    let _ = Self::write_framed(&mut stream, &payload).await;
                }
            });
        }
    }

    async fn request_height(peer: &str) -> Option<u64> {
        // Without a timeout here, a single connection attempt that hangs
        // (rather than cleanly succeeding or failing) would permanently
        // freeze the periodic catch-up loop — it would never proceed to
        // sleep and retry, since it's stuck awaiting this one call forever.
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(peer),
        ).await.ok()?.ok()?;
        let payload = serialize(&P2PMessage::RequestHeight).ok()?;
        Self::write_framed(&mut stream, &payload).await.ok()?;
        let response_bytes = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Self::read_framed(&mut stream),
        ).await.ok()?.ok()?;
        match deserialize::<P2PMessage>(&response_bytes).ok()? {
            P2PMessage::HeightResponse(h) => Some(h),
            _ => None,
        }
    }

    async fn request_blocks(peer: &str, from_height: u64) -> Option<Vec<Block>> {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(peer),
        ).await.ok()?.ok()?;
        let payload = serialize(&P2PMessage::RequestBlocks(from_height)).ok()?;
        Self::write_framed(&mut stream, &payload).await.ok()?;
        let response_bytes = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Self::read_framed(&mut stream),
        ).await.ok()?.ok()?;
        match deserialize::<P2PMessage>(&response_bytes).ok()? {
            P2PMessage::BlocksResponse(blocks) => Some(blocks),
            _ => None,
        }
    }

    pub async fn catch_up(engine: Arc<Mutex<ConsensusEngine>>, db: Arc<DB>, peers: Vec<String>) {
        for peer in &peers {
            let our_height = engine.lock().await.state.chain_height;
            if let Some(peer_height) = Self::request_height(peer).await {
                if peer_height > our_height {
                    println!(
                        "[CATCH-UP] Peer {} is ahead (height {} vs our {}). Requesting blocks {}..={}...",
                        peer, peer_height, our_height, our_height + 1, peer_height
                    );
                    if let Some(blocks) = Self::request_blocks(peer, our_height + 1).await {
                        println!("[CATCH-UP] Received {} block(s) from {}.", blocks.len(), peer);
                        for b in blocks {
                            if !Self::apply_verified_block(b, engine.clone(), db.clone()).await {
                                println!("[CATCH-UP] Stopped applying blocks from {} after a rejection.", peer);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn apply_verified_block(block: Block, engine: Arc<Mutex<ConsensusEngine>>, db: Arc<DB>) -> bool {
        let mut eng = engine.lock().await;

        if block.header.block_height != eng.state.chain_height + 1 {
            println!(
                "[REJECTED] Block height {} does not follow our height {}.",
                block.header.block_height, eng.state.chain_height
            );
            return false;
        }

        let tip_key = format!("block_{}", eng.state.chain_height);
        let tip_bytes = match db.get(tip_key.as_bytes()) {
            Ok(Some(b)) => b,
            _ => {
                println!("[REJECTED] Could not load our own tip block — refusing to apply.");
                return false;
            }
        };
        let tip_block: Block = match deserialize(&tip_bytes) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if block.header.previous_block_hash != tip_block.calculate_hash() {
            println!("[REJECTED] Block {} does not link to our tip — chains have diverged.", block.header.block_height);
            return false;
        }

        if !meets_difficulty(&block.header.calculate_pow_hash(), eng.state.difficulty_bits) {
            println!("[REJECTED] Block {} does not meet the difficulty target.", block.header.block_height);
            return false;
        }

        for tx in &block.transactions {
            if let Err(e) = eng.apply_transaction(&tx.sender, &tx.receiver, tx.amount, &tx.signature) {
                println!("[REJECTED] Block {} contains an invalid transaction: {:?}", block.header.block_height, e);
                return false;
            }
        }

        eng.process_block_reward(block.header.miner.clone());

        if eng.state.chain_height % RETARGET_INTERVAL == 0 {
            let first_height = eng.state.chain_height - RETARGET_INTERVAL;
            if first_height > 0 {
                if let Ok(Some(first_bytes)) = db.get(format!("block_{}", first_height).as_bytes()) {
                    if let Ok(first_block) = deserialize::<Block>(&first_bytes) {
                        eng.retarget_difficulty(first_block.header.timestamp, block.header.timestamp);
                    }
                }
            }
        }

        let block_key = format!("block_{}", eng.state.chain_height);
        let _ = db.put(block_key.as_bytes(), serialize(&block).unwrap());
        let _ = db.put(STATE_KEY, serialize(&eng.state).unwrap());

        println!(
            "[SYNCED] Accepted block {}. Height now {} | Supply {} QL",
            block.header.block_height,
            eng.state.chain_height,
            eng.state.total_minted_supply / COIN
        );
        true
    }

    async fn handle_incoming_block(
        block: Block,
        engine: Arc<Mutex<ConsensusEngine>>,
        db: Arc<DB>,
        peers: Vec<String>,
    ) {
        let current_height = engine.lock().await.state.chain_height;
        if block.header.block_height > current_height + 1 {
            println!(
                "[P2P] Block {} is ahead of our height {} — attempting catch-up from peers.",
                block.header.block_height, current_height
            );
            Self::catch_up(engine.clone(), db.clone(), peers).await;
        }
        Self::apply_verified_block(block, engine, db).await;
    }

    pub async fn start_p2p_server(
        &self,
        engine: Arc<Mutex<ConsensusEngine>>,
        db: Arc<DB>,
        peers: Vec<String>,
        peer_activity: PeerActivity,
    ) -> Result<(), Box<dyn Error>> {
        let address = format!("0.0.0.0:{}", self.p2p_port);
        let listener = TcpListener::bind(&address).await?;
        println!("[NETWORK] P2P Core Engine bound live to interface: {}", address);

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, remote_addr)) = listener.accept().await {
                    let engine_clone = engine.clone();
                    let db_clone = db.clone();
                    let peers_clone = peers.clone();
                    let peer_activity_clone = peer_activity.clone();
                    let peer_ip = remote_addr.ip().to_string();
                    tokio::spawn(async move {
                        let read_result = tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            Self::read_framed(&mut socket),
                        ).await;
                        if let Ok(Ok(payload)) = read_result {
                            if let Ok(msg) = deserialize::<P2PMessage>(&payload) {
                                // Real, direct evidence of who's genuinely connecting
                                // and participating — independent of whatever's in
                                // our own configured peer list, which only reflects
                                // who WE reach out to, not who reaches out to us.
                                {
                                    let mut activity = peer_activity_clone.lock().await;
                                    activity.insert(peer_ip.clone(), chrono::Utc::now().timestamp());
                                }
                                match msg {
                                    P2PMessage::NewBlock(block) => {
                                        Self::handle_incoming_block(block, engine_clone, db_clone, peers_clone).await;
                                    }
                                    P2PMessage::RequestHeight => {
                                        let h = engine_clone.lock().await.state.chain_height;
                                        if let Ok(bytes) = serialize(&P2PMessage::HeightResponse(h)) {
                                            let _ = Self::write_framed(&mut socket, &bytes).await;
                                        }
                                    }
                                    P2PMessage::RequestBlocks(from_height) => {
                                        let our_height = engine_clone.lock().await.state.chain_height;
                                        let mut blocks = Vec::new();
                                        for h in from_height..=our_height {
                                            if let Ok(Some(bytes)) = db_clone.get(format!("block_{}", h).as_bytes()) {
                                                if let Ok(block) = deserialize::<Block>(&bytes) {
                                                    blocks.push(block);
                                                }
                                            }
                                        }
                                        if let Ok(bytes) = serialize(&P2PMessage::BlocksResponse(blocks)) {
                                            let _ = Self::write_framed(&mut socket, &bytes).await;
                                        }
                                    }
                                    P2PMessage::HeightResponse(_) | P2PMessage::BlocksResponse(_) => {}
                                }
                            }
                        }
                    });
                }
            }
        });
        Ok(())
    }

    pub async fn start_rpc_server(
        &self,
        db_path: String,
        engine: Arc<Mutex<ConsensusEngine>>,
        mempool: Arc<Mutex<Vec<Transaction>>>,
        db: Arc<DB>,
        peers: Vec<String>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Result<(), Box<dyn Error>> {
        let address = format!("0.0.0.0:{}", self.rpc_port);
        let listener = TcpListener::bind(&address).await?;
        println!("[WEB RPC] Public Explorer port active on interface: {}", address);

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, remote_addr)) = listener.accept().await {
                    let db_path_clone = db_path.clone();
                    let engine_clone = engine.clone();
                    let mempool_clone = mempool.clone();
                    let db_clone = db.clone();
                    let peers_clone = peers.clone();
                    let rate_limiter_clone = rate_limiter.clone();
                    let client_ip = remote_addr.ip().to_string();
                    tokio::spawn(async move {
                        let request_str = read_http_request(&mut socket).await;
                        if request_str.is_empty() {
                            return;
                        }
                        let first_line = request_str.lines().next().unwrap_or("");

                        if first_line.starts_with("OPTIONS") {
                            let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 86400\r\nConnection: close\r\n\r\n";
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return;
                        }

                        if first_line.starts_with("GET /api/json") {
                            let eng = engine_clone.lock().await;
                            let json_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"status\":\"OPERATIONAL\",\"network\":\"QUANTUM-LATTICE\",\"total_supply_ql\":{},\"chain_height\":{},\"active_database\":\"{}\"}}\r\n",
                                eng.state.total_minted_supply / COIN,
                                eng.state.chain_height,
                                db_path_clone
                            );
                            let _ = socket.write_all(json_response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/blocks/recent") {
                            let current_height = engine_clone.lock().await.state.chain_height;
                            let count: u64 = 20;
                            let start = current_height.saturating_sub(count.saturating_sub(1));

                            let mut items: Vec<String> = Vec::new();
                            let mut h = current_height;
                            loop {
                                if let Ok(Some(bytes)) = db_clone.get(format!("block_{}", h).as_bytes()) {
                                    if let Ok(block) = deserialize::<Block>(&bytes) {
                                        let hash = block.calculate_hash();
                                        items.push(format!(
                                            "{{\"height\":{},\"hash\":\"{}\",\"previous_hash\":\"{}\",\"timestamp\":{},\"miner\":\"{}\",\"tx_count\":{}}}",
                                            block.header.block_height,
                                            hex::encode(&hash),
                                            hex::encode(&block.header.previous_block_hash),
                                            block.header.timestamp,
                                            hex::encode(&block.header.miner),
                                            block.transactions.len()
                                        ));
                                    }
                                }
                                if h == start || h == 0 {
                                    break;
                                }
                                h -= 1;
                            }

                            let json_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"blocks\":[{}]}}\r\n",
                                items.join(",")
                            );
                            let _ = socket.write_all(json_response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/block") {
                            // Full detail on a single block, including its
                            // individual transactions — distinct from
                            // /api/blocks/recent, which only ever returns
                            // summary counts, not the actual sender/receiver/
                            // amount breakdown inside each block.
                            let height_param = extract_query_param(first_line, "height");
                            let response = match height_param.and_then(|h| h.parse::<u64>().ok()) {
                                Some(height) => {
                                    match db_clone.get(format!("block_{}", height).as_bytes()) {
                                        Ok(Some(bytes)) => {
                                            match deserialize::<Block>(&bytes) {
                                                Ok(block) => {
                                                    let hash = block.calculate_hash();
                                                    let tx_items: Vec<String> = block.transactions.iter().map(|tx| {
                                                        format!(
                                                            "{{\"sender\":\"{}\",\"receiver\":\"{}\",\"amount_ql\":{}}}",
                                                            hex::encode(&tx.sender),
                                                            hex::encode(&tx.receiver),
                                                            tx.amount / COIN
                                                        )
                                                    }).collect();
                                                    format!(
                                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"height\":{},\"hash\":\"{}\",\"previous_hash\":\"{}\",\"timestamp\":{},\"miner\":\"{}\",\"nonce\":{},\"transactions\":[{}]}}\r\n",
                                                        block.header.block_height,
                                                        hex::encode(&hash),
                                                        hex::encode(&block.header.previous_block_hash),
                                                        block.header.timestamp,
                                                        hex::encode(&block.header.miner),
                                                        block.header.nonce,
                                                        tx_items.join(",")
                                                    )
                                                }
                                                Err(_) => "HTTP/1.1 500 Internal Server Error\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Could not read that block.\"}\r\n".to_string(),
                                            }
                                        }
                                        _ => "HTTP/1.1 404 Not Found\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"No block at that height.\"}\r\n".to_string(),
                                    }
                                }
                                None => "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected a numeric ?height= parameter.\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/support") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let name = extract_json_string(body, "name");
                            let email = extract_json_string(body, "email");
                            let subject = extract_json_string(body, "subject");
                            let message = extract_json_string(body, "message");
                            let department = extract_json_string(body, "department").unwrap_or_else(|| "ql".to_string());

                            let ip_key = format!("support-ip:{}", client_ip);
                            let ip_ok = rate_limiter_clone.check(&ip_key, 5, 3600).await;

                            let response = if !ip_ok {
                                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Too many messages sent — please wait before sending another.\"}\r\n".to_string()
                            } else {
                                match (name, email, subject, message) {
                                (Some(name), Some(email), Some(subject), Some(message)) => {
                                    if name.trim().is_empty() || email.trim().is_empty() || subject.trim().is_empty() || message.trim().is_empty() {
                                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"All fields are required.\"}\r\n".to_string()
                                    } else if name.len() > 200 || email.len() > 200 || subject.len() > 300 || message.len() > 5000 {
                                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"One of the fields is too long.\"}\r\n".to_string()
                                    } else {
                                        match email::send_support_message(&name, &email, &subject, &message, &department) {
                                            Ok(()) => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\r\n".to_string(),
                                            Err(msg) => format!(
                                                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}\r\n",
                                                msg
                                            ),
                                        }
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: name, email, subject, message\"}\r\n".to_string(),
                                }
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/balance") {
                            let address_hex = extract_query_param(first_line, "address").unwrap_or_default();
                            let response = match hex::decode(&address_hex) {
                                Ok(pk_bytes) => {
                                    let eng = engine_clone.lock().await;
                                    let balance = eng.balance_of(&pk_bytes);
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"address\":\"{}\",\"balance_ql\":{:.8}}}\r\n",
                                        address_hex,
                                        balance as f64 / COIN as f64
                                    )
                                }
                                Err(_) => "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\nInvalid hex address\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/submit_tx") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let sender = extract_json_string(body, "sender");
                            let receiver = extract_json_string(body, "receiver");
                            let signature = extract_json_string(body, "signature");
                            let amount = extract_json_number(body, "amount");

                            let response = match (sender, receiver, signature, amount) {
                                (Some(s_hex), Some(r_hex), Some(sig_hex), Some(amt)) => {
                                    match (hex::decode(&s_hex), hex::decode(&r_hex), hex::decode(&sig_hex)) {
                                        (Ok(sender), Ok(receiver), Ok(signature)) => {
                                            let tx = Transaction::new(sender, receiver, amt, signature);
                                            mempool_clone.lock().await.push(tx);
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"queued\",\"note\":\"included when a miner produces the next block\"}\r\n".to_string()
                                        }
                                        _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Fields must be valid hex\"}\r\n".to_string(),
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: sender, receiver, amount, signature\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/register") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let email = extract_json_string(body, "email");
                            let full_name = extract_json_string(body, "full_name");
                            let address = extract_json_string(body, "address");

                            let register_ip_key = format!("register-ip:{}", client_ip);
                            let register_ip_ok = rate_limiter_clone.check(&register_ip_key, 10, 3600).await;

                            let response = if !register_ip_ok {
                                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Too many registration attempts — please wait before trying again.\"}\r\n".to_string()
                            } else {
                                match (email, address) {
                                (Some(email), Some(address)) => {
                                    match users::register_user(&db_clone, &email, full_name.as_deref(), &address) {
                                        Ok(()) => {
                                            let db_for_email = db_clone.clone();
                                            let email_for_send = email.clone();
                                            tokio::spawn(async move {
                                                let code = match users::create_pending_otp(&db_for_email, &email_for_send) {
                                                    Ok(code) => code,
                                                    Err(e) => { eprintln!("[EMAIL] Could not create OTP: {}", e); return; }
                                                };
                                                let result = tokio::task::spawn_blocking(move || {
                                                    email::send_verification_email(&email_for_send, &code)
                                                }).await;
                                                match result {
                                                    Ok(Ok(())) => println!("[EMAIL] Verification code sent."),
                                                    Ok(Err(e)) => eprintln!("[EMAIL] Failed to send verification code: {}", e),
                                                    Err(e) => eprintln!("[EMAIL] Send task panicked: {}", e),
                                                }
                                            });
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\r\n".to_string()
                                        }
                                        Err(msg) => format!(
                                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}\r\n",
                                            msg
                                        ),
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: email, address (full_name optional)\"}\r\n".to_string(),
                                }
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/verify") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let email = extract_json_string(body, "email");
                            let code = extract_json_string(body, "code");

                            let response = match (email, code) {
                                (Some(email), Some(code)) => {
                                    let email_key = format!("verify-email:{}", email.to_lowercase());
                                    let ip_key = format!("verify-ip:{}", client_ip);
                                    let email_ok = rate_limiter_clone.check(&email_key, 10, 900).await;
                                    let ip_ok = rate_limiter_clone.check(&ip_key, 30, 900).await;

                                    if !email_ok || !ip_ok {
                                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Too many attempts — wait a while before trying again.\"}\r\n".to_string()
                                    } else {
                                        match users::verify_otp(&db_clone, &email, &code) {
                                            Ok(()) => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\r\n".to_string(),
                                            Err(msg) => format!(
                                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}\r\n",
                                                msg
                                            ),
                                        }
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: email, code\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/resend-verification") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let email = extract_json_string(body, "email");

                            let response = match email {
                                Some(email) => {
                                    let email_key = format!("resend-email:{}", email.to_lowercase());
                                    let ip_key = format!("resend-ip:{}", client_ip);
                                    let email_ok = rate_limiter_clone.check(&email_key, 3, 3600).await;
                                    let ip_ok = rate_limiter_clone.check(&ip_key, 8, 3600).await;

                                    if !email_ok || !ip_ok {
                                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Too many requests for this email — wait before trying again.\"}\r\n".to_string()
                                    } else {
                                        match users::create_pending_otp(&db_clone, &email) {
                                            Ok(code) => {
                                                match email::send_verification_email(&email, &code) {
                                                    Ok(()) => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\r\n".to_string(),
                                                    Err(msg) => format!(
                                                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"Could not send email: {}\"}}\r\n",
                                                        msg
                                                    ),
                                                }
                                            }
                                            Err(msg) => format!(
                                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}\r\n",
                                                msg
                                            ),
                                        }
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: email\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/lookup") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let email = extract_json_string(body, "email");

                            let response = match email {
                                Some(email) => {
                                    match users::lookup_user(&db_clone, &email) {
                                        Ok(account) => format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"status\":\"ok\",\"address\":\"{}\"}}\r\n",
                                            account.address
                                        ),
                                        Err(msg) => format!(
                                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}\r\n",
                                            msg
                                        ),
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: email\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/mining/template") {
                            let eng = engine_clone.lock().await;
                            let next_height = eng.state.chain_height + 1;
                            let tip_key = format!("block_{}", eng.state.chain_height);
                            let tip_bytes = db_clone.get(tip_key.as_bytes()).unwrap().unwrap();
                            let tip_block: Block = deserialize(&tip_bytes).unwrap();
                            let prev_hash = tip_block.calculate_hash();
                            let difficulty_bits = eng.state.difficulty_bits;
                            drop(eng);

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"block_height\":{},\"previous_block_hash\":\"{}\",\"merkle_root\":\"{}\",\"version\":1,\"difficulty_bits\":{}}}\r\n",
                                next_height,
                                hex::encode(&prev_hash),
                                hex::encode(vec![0u8; 32]),
                                difficulty_bits
                            );
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/mining/submit") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let miner_hex = extract_json_string(body, "miner");
                            let nonce = extract_json_number(body, "nonce");

                            let response = match (miner_hex.clone(), nonce) {
                                (Some(m_hex), Some(nonce)) => {
                                    match hex::decode(&m_hex) {
                                        Ok(miner_bytes) => {
                                            let mut eng = engine_clone.lock().await;
                                            let next_height = eng.state.chain_height + 1;
                                            let tip_key = format!("block_{}", eng.state.chain_height);
                                            let tip_bytes = db_clone.get(tip_key.as_bytes()).unwrap().unwrap();
                                            let tip_block: Block = deserialize(&tip_bytes).unwrap();
                                            let prev_hash = tip_block.calculate_hash();

                                            let seconds_since_last_block = chrono::Utc::now().timestamp() - tip_block.header.timestamp;
                                            if seconds_since_last_block < crate::consensus::MIN_BLOCK_INTERVAL_SECS {
                                                let wait = crate::consensus::MIN_BLOCK_INTERVAL_SECS - seconds_since_last_block;
                                                format!(
                                                    "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{\"status\":\"rejected\",\"reason\":\"minimum block interval not yet elapsed\",\"retry_after_secs\":{}}}\r\n",
                                                    wait
                                                )
                                            } else {

                                            let candidate_header = BlockHeader {
                                                version: 1,
                                                previous_block_hash: prev_hash.clone(),
                                                merkle_root: vec![0; 32],
                                                timestamp: 0,
                                                block_height: next_height,
                                                miner: miner_bytes.clone(),
                                                nonce,
                                            };
                                            let pow_hash = candidate_header.calculate_pow_hash();

                                            if !meets_difficulty(&pow_hash, eng.state.difficulty_bits) {
                                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\":\"rejected\",\"reason\":\"does not meet difficulty target — template may be stale, refetch and retry\"}\r\n".to_string()
                                            } else {
                                                let mut pending = mempool_clone.lock().await;
                                                let mut accepted = Vec::new();
                                                for tx in pending.drain(..) {
                                                    match eng.apply_transaction(&tx.sender, &tx.receiver, tx.amount, &tx.signature) {
                                                        Ok(()) => accepted.push(tx),
                                                        Err(e) => println!("[REJECTED TX at mine time] {:?}", e),
                                                    }
                                                }
                                                drop(pending);

                                                eng.process_block_reward(miner_bytes.clone());

                                                let final_header = BlockHeader {
                                                    version: 1,
                                                    previous_block_hash: prev_hash,
                                                    merkle_root: vec![0; 32],
                                                    timestamp: chrono::Utc::now().timestamp(),
                                                    block_height: eng.state.chain_height,
                                                    miner: miner_bytes,
                                                    nonce,
                                                };
                                                let block = Block { header: final_header, transactions: accepted };
                                                let block_hash = block.calculate_hash();

                                                if eng.state.chain_height % RETARGET_INTERVAL == 0 {
                                                    let first_height = eng.state.chain_height - RETARGET_INTERVAL;
                                                    if first_height > 0 {
                                                    if let Ok(Some(first_bytes)) = db_clone.get(format!("block_{}", first_height).as_bytes()) {
                                                        if let Ok(first_block) = deserialize::<Block>(&first_bytes) {
                                                            eng.retarget_difficulty(first_block.header.timestamp, block.header.timestamp);
                                                        }
                                                    }
                                                    }
                                                }

                                                let block_key = format!("block_{}", eng.state.chain_height);
                                                db_clone.put(block_key.as_bytes(), serialize(&block).unwrap()).unwrap();
                                                db_clone.put(STATE_KEY, serialize(&eng.state).unwrap()).unwrap();

                                                println!(
                                                    "[MINED] Block {} accepted from external miner {} | Hash {} | Txs {} | Difficulty {} bits",
                                                    eng.state.chain_height,
                                                    m_hex,
                                                    hex::encode(&block_hash),
                                                    block.transactions.len(),
                                                    eng.state.difficulty_bits
                                                );

                                                drop(eng);
                                                P2PNode::broadcast_block(peers_clone.clone(), block).await;

                                                format!(
                                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{\"status\":\"accepted\",\"block_height\":{},\"block_hash\":\"{}\"}}\r\n",
                                                    next_height, hex::encode(&block_hash)
                                                )
                                            }
                                            }
                                        }
                                        Err(_) => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nminer must be valid hex\r\n".to_string(),
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nExpected JSON: {\"miner\":\"hex\",\"nonce\":123}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else if first_line.starts_with("GET /downloads/ql-miner-linux-x64.tar.gz") {
                            match fs::read("ql-miner-linux-x64.tar.gz") {
                                Ok(bytes) => {
                                    let header = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Disposition: attachment; filename=\"ql-miner-linux-x64.tar.gz\"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                                        bytes.len()
                                    );
                                    let _ = socket.write_all(header.as_bytes()).await;
                                    let _ = socket.write_all(&bytes).await;
                                }
                                Err(_) => {
                                    let resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nDownload file not found on this node.\r\n";
                                    let _ = socket.write_all(resp.as_bytes()).await;
                                }
                            }

                        } else if first_line.starts_with("GET /downloads/ql-miner-windows-x64.zip") {
                            match fs::read("ql-miner-windows-x64.zip") {
                                Ok(bytes) => {
                                    let header = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"ql-miner-windows-x64.zip\"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                                        bytes.len()
                                    );
                                    let _ = socket.write_all(header.as_bytes()).await;
                                    let _ = socket.write_all(&bytes).await;
                                }
                                Err(_) => {
                                    let resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nDownload file not found on this node.\r\n";
                                    let _ = socket.write_all(resp.as_bytes()).await;
                                }
                            }

                        } else if first_line.starts_with("GET /downloads/ql-wallet-windows-x64-setup.exe") {
                            match fs::read("ql-wallet_0.1.0_x64-setup.exe") {
                                Ok(bytes) => {
                                    let header = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"ql-wallet-windows-x64-setup.exe\"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                                        bytes.len()
                                    );
                                    let _ = socket.write_all(header.as_bytes()).await;
                                    let _ = socket.write_all(&bytes).await;
                                }
                                Err(_) => {
                                    let resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nDownload file not found on this node.\r\n";
                                    let _ = socket.write_all(resp.as_bytes()).await;
                                }
                            }

                        } else {
                            let html_content = fs::read_to_string("public_explorer.html")
                                .unwrap_or_else(|_| "<h1>public_explorer.html missing</h1>".to_string());
                            let http_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                                html_content.len(),
                                html_content
                            );
                            let _ = socket.write_all(http_response.as_bytes()).await;
                        }
                    });
                }
            }
        });
        Ok(())
    }

    pub async fn start_admin_server(
        &self,
        admin_port: u16,
        engine: Arc<Mutex<ConsensusEngine>>,
        vault_a_pk: Vec<u8>,
        vault_b_pk: Vec<u8>,
        admin_token: String,
        db: Arc<DB>,
        mempool: Arc<Mutex<Vec<Transaction>>>,
        vault_a_seed: Arc<[u8; 32]>,
        vault_b_seed: Arc<[u8; 32]>,
        peer_activity: PeerActivity,
    ) -> Result<(), Box<dyn Error>> {
        let address = format!("127.0.0.1:{}", admin_port);
        let listener = TcpListener::bind(&address).await?;
        println!("[ADMIN] Private control panel bound to LOOPBACK ONLY: {}", address);

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let engine_clone = engine.clone();
                    let va = vault_a_pk.clone();
                    let vb = vault_b_pk.clone();
                    let token = admin_token.clone();
                    let db_clone = db.clone();
                    let mempool_clone = mempool.clone();
                    let va_seed = vault_a_seed.clone();
                    let vb_seed = vault_b_seed.clone();
                    let peer_activity_clone = peer_activity.clone();
                    tokio::spawn(async move {
                        let request_str = read_http_request(&mut socket).await;
                        if request_str.is_empty() {
                            return;
                        }
                        let first_line = request_str.lines().next().unwrap_or("");

                        if first_line.starts_with("OPTIONS") {
                            let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 86400\r\nConnection: close\r\n\r\n";
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return;
                        }

                        let supplied_token = extract_query_param(first_line, "token").unwrap_or_default();
                        if supplied_token != token {
                            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\nMissing or incorrect admin token. Load this dashboard as: http://127.0.0.1:PORT/?token=YOUR_TOKEN (see <prefix>_admin_token.txt)\r\n";
                            let _ = socket.write_all(resp.as_bytes()).await;
                            return;
                        }

                        if first_line.starts_with("GET /api/admin/json") {
                            let eng = engine_clone.lock().await;
                            let json_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"chain_height\":{},\"total_minted_supply\":{},\"vault_a_balance\":{},\"vault_b_balance\":{},\"vault_a_address\":\"{}\",\"vault_b_address\":\"{}\",\"mining_pool_remaining\":{}}}\r\n",
                                eng.state.chain_height,
                                eng.state.total_minted_supply / COIN,
                                eng.balance_of(&va) / COIN,
                                eng.balance_of(&vb) / COIN,
                                hex::encode(&va),
                                hex::encode(&vb),
                                (crate::consensus::MINING_REWARD_POOL.saturating_sub(
                                    eng.state.total_minted_supply.saturating_sub(
                                        crate::consensus::VAULT_A_ALLOCATION + crate::consensus::VAULT_B_ALLOCATION
                                    )
                                )) / COIN
                            );
                            let _ = socket.write_all(json_response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/admin/peers") {
                            // Real, direct visibility into who's genuinely
                            // contacted this node's P2P port — not just who's
                            // in our own configured peer list.
                            let activity = peer_activity_clone.lock().await;
                            let now = chrono::Utc::now().timestamp();
                            let mut items: Vec<String> = Vec::new();
                            for (addr, last_seen) in activity.iter() {
                                let seconds_ago = now - last_seen;
                                items.push(format!(
                                    "{{\"address\":\"{}\",\"seconds_ago\":{}}}",
                                    addr, seconds_ago
                                ));
                            }
                            let json_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"count\":{},\"peers\":[{}]}}\r\n",
                                items.len(),
                                items.join(",")
                            );
                            let _ = socket.write_all(json_response.as_bytes()).await;

                        } else if first_line.starts_with("GET /api/admin/users") {
                            let accounts = users::list_all_users(&db_clone);
                            let mut items = Vec::with_capacity(accounts.len());
                            for a in &accounts {
                                let name_json = match &a.full_name {
                                    Some(n) => format!("\"{}\"", n.replace('"', "\\\"")),
                                    None => "null".to_string(),
                                };
                                items.push(format!(
                                    "{{\"email\":\"{}\",\"full_name\":{},\"address\":\"{}\",\"created_at\":{},\"verified\":{}}}",
                                    a.email.replace('"', "\\\""),
                                    name_json,
                                    a.address,
                                    a.created_at,
                                    a.verified
                                ));
                            }
                            let json_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"count\":{},\"users\":[{}]}}\r\n",
                                accounts.len(),
                                items.join(",")
                            );
                            let _ = socket.write_all(json_response.as_bytes()).await;

                        } else if first_line.starts_with("POST /api/admin/send") {
                            let body = request_str.split("\r\n\r\n").nth(1).unwrap_or("");
                            let from_vault = extract_json_string(body, "from_vault");
                            let to_hex = extract_json_string(body, "to");
                            let amount_ql = extract_json_number(body, "amount");

                            let response = match (from_vault.as_deref(), to_hex, amount_ql) {
                                (Some(from), Some(to_hex), Some(amount_ql)) => {
                                    let sender_and_seed: Option<(&[u8], &[u8; 32])> = match from {
                                        "a" => Some((&va, va_seed.as_ref())),
                                        "b" => Some((&vb, vb_seed.as_ref())),
                                        _ => None,
                                    };

                                    match sender_and_seed {
                                        None => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"from_vault must be 'a' or 'b'\"}\r\n".to_string(),
                                        Some((sender_pk, seed_bytes)) => {
                                            match hex::decode(&to_hex) {
                                                Ok(receiver) => {
                                                    let amount_smallest = (amount_ql as f64 * COIN as f64).round() as u64;
                                                    let mut message = Vec::with_capacity(sender_pk.len() + receiver.len() + 8);
                                                    message.extend_from_slice(sender_pk);
                                                    message.extend_from_slice(&receiver);
                                                    message.extend_from_slice(&amount_smallest.to_le_bytes());

                                                    let signature = sign_with_seed_bytes(seed_bytes, &message);
                                                    let tx = Transaction::new(sender_pk.to_vec(), receiver, amount_smallest, signature);
                                                    mempool_clone.lock().await.push(tx);

                                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"status\":\"queued\",\"note\":\"included when a miner produces the next block\"}\r\n".to_string()
                                                }
                                                Err(_) => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"'to' must be valid hex\"}\r\n".to_string(),
                                            }
                                        }
                                    }
                                }
                                _ => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: from_vault ('a' or 'b'), to (hex address), amount\"}\r\n".to_string(),
                            };
                            let _ = socket.write_all(response.as_bytes()).await;

                        } else {
                            let html_content = fs::read_to_string("admin_dashboard.html")
                                .unwrap_or_else(|_| "<h1>admin_dashboard.html missing</h1>".to_string());
                            let http_response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                                html_content.len(),
                                html_content
                            );
                            let _ = socket.write_all(http_response.as_bytes()).await;
                        }
                    });
                }
            }
        });
        Ok(())
    }
}
