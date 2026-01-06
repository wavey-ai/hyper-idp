use auth::Auth;
use std::sync::Arc;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let idp_url = env::var("IDP_URL").unwrap_or_else(|_| "https://local.wavey.io:8443".into());
    let poll_interval = env::var("POLL_INTERVAL")
        .unwrap_or_else(|_| "10".into())
        .parse()
        .unwrap();

    println!("Starting auth poller");
    println!("IDP URL: {}", idp_url);
    println!("Poll interval: {}s", poll_interval);

    let auth = Arc::new(Auth::new(idp_url, poll_interval));
    let _shutdown = auth.clone().start_polling();

    // Test loop - check allow list periodically
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let users = auth.get_allowed_users();
        println!("Current allowed users ({}):", users.len());
        for user_id in &users {
            println!("  - {}", user_id);
        }

        // Test a specific user ID
        let test_id: u64 = 12345;
        println!("Is {} allowed? {}", test_id, auth.is_allowed(test_id));
    }
}
