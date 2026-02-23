use crate::rate_limiter::RateLimiter;
use colored::*;
use indicatif::ProgressBar;
use std::fs;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct BypassBypass {
    pub url: Url,
    // pub original_status: u16,
    pub bypass_url: Url,
    pub method: String,
    pub technique: String,
    // pub response_size: u64,
    pub severity: String,
    pub headers: String,
}

use crate::reporter::Reporter;

pub struct BypassScanner<'a> {
    target_url: Url,
    directories: Vec<String>,
    header_payloads: Vec<(String, String)>,
    url_payloads: Vec<String>,
    methods: Vec<String>,
    user_agents: Vec<String>,
    pb: &'a ProgressBar,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

struct CheckBypassArgs<'a> {
    client: &'a reqwest::Client,
    original_url: &'a Url,
    technique_url: Url,
    method: &'a str,
    technique: String,
    original_body: &'a str,
    headers: Option<&'a [(&'a str, &'a str)]>,
}

impl<'a> BypassScanner<'a> {
    pub fn new(
        target_url: Url,
        pb: &'a ProgressBar,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let directories = Self::load_list("wordlists/directories.txt");
        let header_payloads = Self::load_header_payloads();
        let url_payloads = Self::load_list("wordlists/bypass_403/url_payloads.txt");
        let methods = Self::load_list("wordlists/methods.txt");
        let user_agents = Self::load_list("wordlists/user_agents.txt");

        Self {
            target_url,
            directories,
            header_payloads,
            url_payloads,
            methods,
            user_agents,
            pb,
            reporter,
            rate_limiter,
        }
    }

    fn load_list(path: &str) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                list.push(line);
            }
        }
        if list.is_empty() {
            list.push("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string());
        }
        list
    }

    fn load_header_payloads() -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open("webhunter/wordlists/http_headers.txt") {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    payloads.push((parts[0].to_string(), parts[1].trim().to_string()));
                }
            }
        }
        payloads
    }

    pub async fn scan(&self) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        for directory in &self.directories {
            let test_url = match self.target_url.join(&format!("{}/", directory)) {
                Ok(url) => url,
                Err(_) => continue,
            };

            self.rate_limiter.wait().await;
            match client.get(test_url.clone()).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    self.pb.inc(1);

                    if status == 403 {
                        if let Ok(original_body) = response.text().await {
                            if let Some(bypass) = self
                                .try_bypass_directory(
                                    &client,
                                    test_url.clone(),
                                    directory,
                                    &original_body,
                                )
                                .await
                            {
                                self.reporter.report_403_bypass(&bypass);
                            }
                        }
                    }
                }
                Err(_) => {
                    self.pb.inc(1);
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn try_bypass_directory(
        &self,
        client: &reqwest::Client,
        original_url: Url,
        directory: &str,
        original_body: &str,
    ) -> Option<BypassBypass> {
        let bypass_techniques = self.generate_bypass_techniques(&original_url, directory);

        for (technique_url, technique_name) in bypass_techniques {
            // First, check with GET
            let args = CheckBypassArgs {
                client,
                original_url: &original_url,
                technique_url: technique_url.clone(),
                method: "GET",
                technique: technique_name.clone(),
                original_body,
                headers: None,
            };
            self.rate_limiter.wait().await;
            if let Some((bypass, status, _body)) = self.check_bypass(args).await {
                print_fancy_bypass(&bypass, status);
                return Some(bypass);
            }

            // Then, check with other methods
            for method in &self.methods {
                let combined_technique = format!("{} via {}", technique_name, method);
                let args = CheckBypassArgs {
                    client,
                    original_url: &original_url,
                    technique_url: technique_url.clone(),
                    method,
                    technique: combined_technique,
                    original_body,
                    headers: None,
                };
                self.rate_limiter.wait().await;
                if let Some((bypass, status, _body)) = self.check_bypass(args).await {
                    print_fancy_bypass(&bypass, status);
                    return Some(bypass);
                }
            }

            for (header_name, header_value) in &self.header_payloads {
                for user_agent in &self.user_agents {
                    let headers = vec![
                        (header_name.as_str(), header_value.as_str()),
                        ("User-Agent", user_agent.as_str()),
                    ];
                    let args = CheckBypassArgs {
                        client,
                        original_url: &original_url,
                        technique_url: technique_url.clone(),
                        method: "GET",
                        technique: "Header Spoofing".to_string(),
                        original_body,
                        headers: Some(&headers),
                    };
                    self.rate_limiter.wait().await;
                    if let Some((bypass, status, _body)) = self.check_bypass(args).await {
                        print_fancy_bypass(&bypass, status);
                        return Some(bypass);
                    }
                }
            }
        }
        None
    }

    fn generate_bypass_techniques(
        &self,
        original_url: &Url,
        directory: &str,
    ) -> Vec<(Url, String)> {
        let mut techniques = Vec::new();
        for payload in &self.url_payloads {
            if let Ok(url) = original_url.join(&format!("{}{}", directory, payload)) {
                techniques.push((url, payload.to_string()));
            }
        }
        techniques
    }

    async fn check_bypass(&self, args: CheckBypassArgs<'_>) -> Option<(BypassBypass, u16, String)> {
        let mut request_builder = match args.method {
            "GET" => args.client.get(args.technique_url.clone()),
            "POST" => args.client.post(args.technique_url.clone()),
            "PUT" => args.client.put(args.technique_url.clone()),
            "PATCH" => args.client.patch(args.technique_url.clone()),
            "HEAD" => args.client.head(args.technique_url.clone()),
            "TRACE" => args
                .client
                .request(reqwest::Method::TRACE, args.technique_url.clone()),
            "OPTIONS" => args
                .client
                .request(reqwest::Method::OPTIONS, args.technique_url.clone()),
            _ => return None,
        };

        let mut header_str = String::new();
        if let Some(headers) = args.headers {
            for (key, value) in headers {
                request_builder = request_builder.header(*key, *value);
                header_str.push_str(&format!("{}: {}\n", key, value));
            }
        }

        if let Ok(response) = request_builder.send().await {
            let status = response.status().as_u16();
            if status == 200 {
                if let Ok(body) = response.text().await {
                    if body != args.original_body {
                        let bypass = BypassBypass {
                            url: args.original_url.clone(),
                            bypass_url: args.technique_url,
                            method: args.method.to_string(),
                            technique: args.technique,
                            severity: "High".to_string(),
                            headers: header_str,
                        };
                        return Some((bypass, status, body));
                    }
                }
            }
        }
        None
    }
}

fn print_fancy_bypass(bypass: &BypassBypass, status: u16) {
    println!("{}", "[+] 403 Bypassed!".green().bold());
    println!("{}", "-----------------".cyan());
    println!("{} {}", "URL         :".cyan(), bypass.bypass_url);
    println!("{} {}", "Method      :".cyan(), bypass.method);
    println!("{} {}", "Payload     :".cyan(), bypass.technique);
    println!(
        "{} {} {}",
        "Status Code :".cyan(),
        status.to_string().green(),
        "OK".green()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito;

    fn create_test_scanner(base_url: Url) -> BypassScanner<'static> {
        let reporter = Box::leak(Box::new(Arc::new(Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ))));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_millis(0)));
        let pb = Box::leak(Box::new(ProgressBar::hidden()));

        let mut scanner = BypassScanner::new(base_url, pb, reporter, rate_limiter);

        // Override wordlists with deterministic test data
        scanner.url_payloads = vec!["/.".to_string(), "%20".to_string(), ";".to_string()];
        scanner.methods = vec!["POST".to_string(), "TRACE".to_string()];
        scanner.header_payloads = vec![
            ("X-Custom-IP".to_string(), "127.0.0.1".to_string()),
            ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
        ];
        scanner.user_agents = vec!["TestAgent".to_string()];

        scanner
    }

    #[test]
    fn test_generate_bypass_techniques() {
        let url = Url::parse("http://example.com").unwrap();
        let scanner = create_test_scanner(url.clone());

        let techniques = scanner.generate_bypass_techniques(&url, "admin");

        assert!(!techniques.is_empty());
        // Check if our injected payloads are present
        let payload_strings: Vec<String> = techniques.iter().map(|(_, p)| p.clone()).collect();
        assert!(payload_strings.contains(&"/.".to_string()));
        assert!(payload_strings.contains(&"%20".to_string()));
    }

    #[test]
    fn test_check_bypass_success() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let scanner = create_test_scanner(url.clone());

        // Mock the bypass target
        let _m = server
            .mock("GET", "/admin/bypass")
            .with_status(200)
            .with_body("Bypassed Content")
            .create();

        let technique_url = url.join("/admin/bypass").unwrap();

        let args = CheckBypassArgs {
            client: &reqwest::Client::new(),
            original_url: &url,
            technique_url: technique_url.clone(),
            method: "GET",
            technique: "URL Manipulation".to_string(),
            original_body: "Forbidden",
            headers: None,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.check_bypass(args));

        assert!(result.is_some());
        let (bypass, status, body) = result.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "Bypassed Content");
        assert_eq!(bypass.bypass_url, technique_url);
    }

    #[test]
    fn test_check_bypass_failure_same_body() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let scanner = create_test_scanner(url.clone());

        // Mock 200 OK but with same content (e.g. custom error page returning 200)
        let _m = server
            .mock("GET", "/admin/.")
            .with_status(200)
            .with_body("Forbidden") // Same as original
            .create();

        let technique_url = url.join("/admin/.").unwrap();

        let args = CheckBypassArgs {
            client: &reqwest::Client::new(),
            original_url: &url,
            technique_url,
            method: "GET",
            technique: "URL Manipulation".to_string(),
            original_body: "Forbidden",
            headers: None,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.check_bypass(args));

        assert!(
            result.is_none(),
            "Should not report bypass if body content is identical"
        );
    }

    #[test]
    fn test_check_bypass_header_spoofing() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let scanner = create_test_scanner(url.clone());

        // Mock endpoint requiring specific header
        let _m = server
            .mock("GET", "/admin")
            .match_header("X-Custom-IP", "127.0.0.1")
            .with_status(200)
            .with_body("Admin Panel")
            .create();

        let technique_url = url.join("/admin").unwrap();
        let headers = vec![("X-Custom-IP", "127.0.0.1")];

        let args = CheckBypassArgs {
            client: &reqwest::Client::new(),
            original_url: &url,
            technique_url,
            method: "GET",
            technique: "Header Spoofing".to_string(),
            original_body: "Access Denied",
            headers: Some(&headers),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.check_bypass(args));

        assert!(result.is_some());
        let (_, status, body) = result.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "Admin Panel");
    }

    #[test]
    fn test_check_bypass_method_override() {
        let mut server = mockito::Server::new();
        let url = Url::parse(&server.url()).unwrap();
        let scanner = create_test_scanner(url.clone());

        // Mock POST request bypass
        let _m = server
            .mock("POST", "/admin")
            .with_status(200)
            .with_body("Action Completed")
            .create();

        let technique_url = url.join("/admin").unwrap();

        let args = CheckBypassArgs {
            client: &reqwest::Client::new(),
            original_url: &url,
            technique_url,
            method: "POST",
            technique: "Method Override".to_string(),
            original_body: "Get Out",
            headers: None,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.check_bypass(args));

        assert!(result.is_some());
        let (_, status, _) = result.unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn test_scanner_creation() {
        let url = Url::parse("http://example.com").unwrap();
        let scanner = create_test_scanner(url.clone());

        // Verify lists are populated (from our override)
        assert!(!scanner.url_payloads.is_empty());
        assert!(!scanner.methods.is_empty());
        assert!(!scanner.header_payloads.is_empty());
    }
}
