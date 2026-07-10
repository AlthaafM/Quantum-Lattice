// Sends real emails via Gmail's SMTP relay, using an App Password loaded
// from a local secrets.env file (never hardcoded, never committed anywhere,
// same pattern already used elsewhere in this project's other services).
//
// This is entirely separate from wallet security — it only ever sends a
// short-lived verification code to an email address, and never touches or
// needs anyone's actual keys.
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

fn smtp_config() -> Result<(String, String, String), String> {
    let username = std::env::var("QL_SMTP_USERNAME")
        .map_err(|_| "QL_SMTP_USERNAME not set in secrets.env".to_string())?;
    let app_password = std::env::var("QL_SMTP_APP_PASSWORD")
        .map_err(|_| "QL_SMTP_APP_PASSWORD not set in secrets.env".to_string())?;
    let from_address = std::env::var("QL_SMTP_FROM")
        .unwrap_or_else(|_| "ql-wallet@futuristicai.co.za".to_string());
    Ok((username, app_password, from_address))
}

/// Sends the verification code email. Runs the actual (blocking) SMTP send
/// on a background thread via spawn_blocking at the call site — this
/// function itself is plain, synchronous code.
pub fn send_verification_email(to_email: &str, code: &str) -> Result<(), String> {
    let (smtp_username, smtp_password, from_address) = smtp_config()?;

    let from_mailbox = Mailbox::new(
        Some("Quantum-Lattice Wallet".to_string()),
        from_address.parse().map_err(|e| format!("Invalid from address: {}", e))?,
    );
    let to_mailbox: Mailbox = to_email
        .parse()
        .map_err(|e| format!("Invalid recipient address: {}", e))?;

    let body = format!(
        "Your Quantum-Lattice verification code is: {}\n\n\
         This code expires in 15 minutes. If you didn't request this, you can safely ignore this email.\n\n\
         — Quantum-Lattice, by FuturisticAI",
        code
    );

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject("Your Quantum-Lattice verification code")
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|e| format!("Could not build email: {}", e))?;

    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .map_err(|e| format!("Could not set up mail relay: {}", e))?
        .credentials(creds)
        .build();

    mailer
        .send(&email)
        .map_err(|e| format!("Could not send email: {}", e))?;
    Ok(())
}

/// Maps a department keyword to its real destination address. Deliberately
/// an allowlist, not a pass-through — a caller can never make an arbitrary
/// address the destination, only one of these known, fixed ones.
fn resolve_support_destination(department: &str) -> String {
    match department {
        "mss" => "support-mss@futuristicai.co.za".to_string(),
        "info" => "Info@futuristicai.co.za".to_string(),
        "msm" => "support-msm@futuristicai.co.za".to_string(),
        "aqf" => "support-aqf@futuristicai.co.za".to_string(),
        _ => std::env::var("QL_SUPPORT_TO").unwrap_or_else(|_| "support-ql@futuristicai.co.za".to_string()),
    }
}

/// Sends a support form submission to the resolved department inbox, with
/// Reply-To set to whoever submitted it — so replying from Gmail goes
/// straight back to them, not to the sending address.
pub fn send_support_message(name: &str, reply_email: &str, subject: &str, message: &str, department: &str) -> Result<(), String> {
    let (smtp_username, smtp_password, _) = smtp_config()?;

    let from_address = "ql-wallet@futuristicai.co.za";
    let to_address = resolve_support_destination(department);

    let from_mailbox = Mailbox::new(
        Some("Quantum-Lattice Support Form".to_string()),
        from_address.parse().map_err(|e| format!("Invalid from address: {}", e))?,
    );
    let to_mailbox: Mailbox = to_address
        .parse()
        .map_err(|e| format!("Invalid support inbox address: {}", e))?;
    let reply_mailbox: Mailbox = reply_email
        .parse()
        .map_err(|_| "That doesn't look like a valid email address.".to_string())?;

    let body = format!(
        "New support message from the public explorer.\n\n\
         Name: {}\n\
         Reply to: {}\n\
         Subject: {}\n\n\
         {}\n",
        name, reply_email, subject, message
    );

    let email = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .reply_to(reply_mailbox)
        .subject(format!("[QL Support] {}", subject))
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|e| format!("Could not build email: {}", e))?;

    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .map_err(|e| format!("Could not set up mail relay: {}", e))?
        .credentials(creds)
        .build();

    mailer
        .send(&email)
        .map_err(|e| format!("Could not send email: {}", e))?;
    Ok(())
}
