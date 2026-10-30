use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
};
use tokio_iecp5::console::Console;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let address: SocketAddr = std::env::var("IEC104_API_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:24040".into())
        .parse()?;
    if !address.ip().is_loopback() {
        anyhow::bail!("Control API must bind to a loopback address");
    }
    // RandomState supplies OS-seeded keys; do not put a fixed secret in the app.
    let token = std::env::var("IEC104_TOKEN").unwrap_or_else(|_| {
        format!(
            "{:016x}{:016x}",
            RandomState::new().build_hasher().finish(),
            RandomState::new().build_hasher().finish()
        )
    });
    if token.len() < 16 {
        anyhow::bail!("IEC104_TOKEN must be at least 16 characters");
    }
    let console = Console::new(token.clone());
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!(
        "IEC104 Studio control API: http://{}",
        listener.local_addr()?
    );
    println!("API Token: {token}");
    println!("Paste the token into the NSH app. No IEC104 connection is started automatically.");
    let result = axum::serve(listener, console.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    console.shutdown().await;
    result?;
    Ok(())
}
