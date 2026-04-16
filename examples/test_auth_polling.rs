use reqwest::Client;
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let idp_url = env::var("IDP_URL").unwrap_or_else(|_| "https://local.wavey.io:8443".into());
    let poll_interval = env::var("POLL_INTERVAL")
        .unwrap_or_else(|_| "10".into())
        .parse::<u64>()?;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Polling active sessions from {idp_url}/users every {poll_interval}s");

    loop {
        let response = client
            .get(format!("{idp_url}/users"))
            .send()
            .await?
            .error_for_status()?;
        let body = response.text().await?;
        println!("active users: {body}");
        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
    }
}
