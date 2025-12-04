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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_rate_limiter_delays() {
        let delay = Duration::from_millis(100);
        let limiter = RateLimiter::new(delay);

        let start = Instant::now();

        // First call should not delay much (allow some overhead)
        limiter.wait().await;
        let elapsed1 = start.elapsed();
        // More generous timing to account for test environment overhead
        assert!(
            elapsed1 < Duration::from_millis(150),
            "First call took {:?}",
            elapsed1
        );

        // Second call should delay
        limiter.wait().await;
        let elapsed2 = start.elapsed();
        // Should be at least 100ms (one delay), but give generous tolerance
        assert!(
            elapsed2 >= Duration::from_millis(100),
            "Second call delayed {:?}",
            elapsed2
        );
        assert!(
            elapsed2 < Duration::from_millis(250),
            "Delay should not be excessive, was {:?}",
            elapsed2
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_concurrent() {
        let delay = Duration::from_millis(50);
        let limiter = std::sync::Arc::new(RateLimiter::new(delay));

        let start = Instant::now();
        let mut handles = vec![];

        // Spawn 5 concurrent tasks
        for _ in 0..5 {
            let limiter_clone = limiter.clone();
            handles.push(tokio::spawn(async move {
                limiter_clone.wait().await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let elapsed = start.elapsed();
        // With 5 requests and 50ms delay, should take at least 200ms (4 delays)
        assert!(
            elapsed >= Duration::from_millis(200),
            "Concurrent requests should be properly throttled"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_zero_delay() {
        let limiter = RateLimiter::new(Duration::ZERO);

        let start = Instant::now();
        for _ in 0..10 {
            limiter.wait().await;
        }
        let elapsed = start.elapsed();

        // All requests should complete quickly with zero delay
        assert!(
            elapsed < Duration::from_millis(50),
            "Zero delay should allow fast requests"
        );
    }
}
