use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct RateLimiter {
    delay: Duration,
    last_request: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            last_request: Mutex::new(Instant::now()),
        }
    }

    pub async fn wait(&self) {
        let mut last_request = self.last_request.lock().await;
        let elapsed = last_request.elapsed();
        if elapsed < self.delay {
            tokio::time::sleep(self.delay - elapsed).await;
        }
        *last_request = Instant::now();
    }
}
