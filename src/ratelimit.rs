// Simple in-memory rate limiter — fixed windows per key, not a sliding
// window or token bucket. That's a deliberate simplification: this only
// needs to stop obvious abuse (email bombing, OTP brute-forcing), not
// provide precise traffic shaping. Resets on node restart, which is fine
// for this purpose.
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

pub struct RateLimiter {
    windows: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { windows: Mutex::new(HashMap::new()) }
    }

    /// Returns true if this call is allowed (and counts it against the
    /// limit). Returns false if key has already hit max_count within
    /// the last window_secs.
    pub async fn check(&self, key: &str, max_count: u32, window_secs: u64) -> bool {
        let mut map = self.windows.lock().await;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((0, now));

        if now.duration_since(entry.1).as_secs() > window_secs {
            *entry = (1, now);
            true
        } else if entry.0 < max_count {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}
