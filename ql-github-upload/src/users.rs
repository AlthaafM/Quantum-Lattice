// Lightweight email directory layer for admin visibility — purely a record
// of "this email is associated with this address." No password, no login:
// a wallet address isn't secret information (it's what you'd hand someone
// to receive funds), so there's nothing here worth gating behind a
// password.
//
// Email verification (OTP) adds real confidence that the email actually
// belongs to whoever registered it — but verification status is purely
// informational for admin visibility. It never gates wallet creation or
// use; a wallet is already fully functional the moment it's created,
// regardless of whether its linked email ever gets verified.
//
// Completely separate from wallet security, same as before: this module
// never sees, stores, or needs anyone's actual ML-DSA secret key or seed.
use serde::{Serialize, Deserialize};
use rocksdb::DB;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserAccount {
    pub email: String,
    pub full_name: Option<String>,
    pub address: String, // hex-encoded ML-DSA-65 public key — this wallet's identity, not a secret
    pub created_at: i64,
    pub verified: bool,
}

/// Matches the account format used before the verified field existed.
/// Bincode has no built-in support for schema evolution (unlike JSON, it
/// isn't self-describing), so reading older records needs this explicit
/// fallback rather than a #[serde(default)] attribute, which wouldn't
/// reliably work here. Records from the (now content of) even older
/// email+password schema, from before this, still won't recover — but the
/// two most recent formats (this one, and the current one above) both do.
#[derive(Serialize, Deserialize, Clone)]
struct UserAccountLegacyNoVerified {
    pub email: String,
    pub full_name: Option<String>,
    pub address: String,
    pub created_at: i64,
}

impl From<UserAccountLegacyNoVerified> for UserAccount {
    fn from(legacy: UserAccountLegacyNoVerified) -> Self {
        UserAccount {
            email: legacy.email,
            full_name: legacy.full_name,
            address: legacy.address,
            created_at: legacy.created_at,
            verified: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct PendingOtp {
    code: String,
    expires_at: i64,
}

const OTP_VALID_SECONDS: i64 = 15 * 60; // 15 minutes

fn user_key(email: &str) -> Vec<u8> {
    format!("user:{}", email.trim().to_lowercase()).into_bytes()
}

fn otp_key(email: &str) -> Vec<u8> {
    format!("otp:{}", email.trim().to_lowercase()).into_bytes()
}

pub fn register_user(db: &Arc<DB>, email: &str, full_name: Option<&str>, address_hex: &str) -> Result<(), String> {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        return Err("Enter a valid email address.".to_string());
    }
    if address_hex.trim().is_empty() {
        return Err("Missing wallet address.".to_string());
    }

    let key = user_key(email);
    if db.get(&key).map_err(|e| e.to_string())?.is_some() {
        return Err("An account with this email already exists.".to_string());
    }

    let account = UserAccount {
        email: email.to_string(),
        full_name: full_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        address: address_hex.trim().to_string(),
        created_at: chrono::Utc::now().timestamp(),
        verified: false,
    };
    let bytes = bincode::serialize(&account).map_err(|e| e.to_string())?;
    db.put(&key, bytes).map_err(|e| e.to_string())?;
    Ok(())
}

/// Look up which address an email is linked to — informational only, no
/// credential required, since the underlying information (a wallet
/// address) isn't sensitive.
pub fn lookup_user(db: &Arc<DB>, email: &str) -> Result<UserAccount, String> {
    let key = user_key(email);
    let bytes = db
        .get(&key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No account with this email.".to_string())?;
    if let Ok(account) = bincode::deserialize::<UserAccount>(&bytes) {
        return Ok(account);
    }
    bincode::deserialize::<UserAccountLegacyNoVerified>(&bytes)
        .map(UserAccount::from)
        .map_err(|e| e.to_string())
}

/// Admin-only: list every registered account. Loopback + admin-token gated
/// at the call site (network.rs), same as the rest of the admin panel.
pub fn list_all_users(db: &Arc<DB>) -> Vec<UserAccount> {
    let mut users = Vec::new();
    for item in db.prefix_iterator(b"user:") {
        if let Ok((key, value)) = item {
            if !key.starts_with(b"user:") {
                break; // rocksdb prefix_iterator can run past the prefix at the end of the keyspace
            }
            if let Ok(account) = bincode::deserialize::<UserAccount>(&value) {
                users.push(account);
            } else if let Ok(legacy) = bincode::deserialize::<UserAccountLegacyNoVerified>(&value) {
                users.push(UserAccount::from(legacy));
            }
            // Records under an even older schema (from before full_name/
            // verified existed) still won't deserialize and are silently
            // skipped — harmless, just means those particular test
            // accounts won't show until re-registered.
        }
    }
    users
}

/// Generates a random 6-digit numeric code and stores it, replacing any
/// previous pending code for this email. Returns the code so the caller
/// can email it — this function never sends anything itself.
pub fn create_pending_otp(db: &Arc<DB>, email: &str) -> Result<String, String> {
    let mut digits = [0u8; 6];
    getrandom::fill(&mut digits).map_err(|e| e.to_string())?;
    let code: String = digits.iter().map(|b| (b'0' + (b % 10)) as char).collect();

    let pending = PendingOtp {
        code: code.clone(),
        expires_at: chrono::Utc::now().timestamp() + OTP_VALID_SECONDS,
    };
    let bytes = bincode::serialize(&pending).map_err(|e| e.to_string())?;
    db.put(otp_key(email), bytes).map_err(|e| e.to_string())?;
    Ok(code)
}

/// Checks a submitted code against the stored pending one. On success,
/// marks the account verified and clears the pending code so it can't be
/// reused.
pub fn verify_otp(db: &Arc<DB>, email: &str, submitted_code: &str) -> Result<(), String> {
    let key = otp_key(email);
    let bytes = db
        .get(&key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No verification code was requested for this email — try registering again.".to_string())?;
    let pending: PendingOtp = bincode::deserialize(&bytes).map_err(|e| e.to_string())?;

    if chrono::Utc::now().timestamp() > pending.expires_at {
        db.delete(&key).ok();
        return Err("This code has expired — request a new one.".to_string());
    }
    if submitted_code.trim() != pending.code {
        return Err("Incorrect code.".to_string());
    }

    let user_key_bytes = user_key(email);
    let user_bytes = db
        .get(&user_key_bytes)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No account found for this email.".to_string())?;
    let mut account: UserAccount = bincode::deserialize(&user_bytes).map_err(|e| e.to_string())?;
    account.verified = true;
    let updated_bytes = bincode::serialize(&account).map_err(|e| e.to_string())?;
    db.put(&user_key_bytes, updated_bytes).map_err(|e| e.to_string())?;

    db.delete(&key).ok(); // consume the code so it can't be reused
    Ok(())
}
