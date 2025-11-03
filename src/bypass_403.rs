use crate::rate_limiter::RateLimiter;
use crate::snapshot;
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
        let directories = Self::load_list("webhunter/wordlists/directories.txt");
        let header_payloads = Self::load_header_payloads();
        let url_payloads = Self::load_list("webhunter/wordlists/bypass_403/url_payloads.txt");
        let methods = Self::load_list("webhunter/wordlists/methods.txt");
        let user_agents = Self::load_list("webhunter/wordlists/user_agents.txt");

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
                            if let Some(bypass) = self.try_bypass_directory(&client, test_url.clone(), directory, &original_body).await {
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

    async fn try_bypass_directory(&self, client: &reqwest::Client, original_url: Url, directory: &str, original_body: &str) -> Option<BypassBypass> {
        let bypass_techniques = self.generate_bypass_techniques(&original_url, directory);
        let domain = self.target_url.domain().unwrap_or("");

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
            if let Some((bypass, status, body)) = self.check_bypass(args).await {
                print_fancy_bypass(&bypass, status);
                if let Err(e) = snapshot::take_snapshot(bypass.bypass_url.clone(), domain.to_string(), bypass.method.clone(), bypass.technique.clone(), body).await {
                    eprintln!("\nFailed to take snapshot for {}: {}", &bypass.bypass_url, e);
                }
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
                if let Some((bypass, status, body)) = self.check_bypass(args).await {
                    print_fancy_bypass(&bypass, status);
                    if let Err(e) = snapshot::take_snapshot(bypass.bypass_url.clone(), domain.to_string(), bypass.method.clone(), bypass.technique.clone(), body).await {
                        eprintln!("\nFailed to take snapshot for {}: {}", &bypass.bypass_url, e);
                    }
                    return Some(bypass);
                }
            }

            for (header_name, header_value) in &self.header_payloads {
                for user_agent in &self.user_agents {
                    let headers = vec![(header_name.as_str(), header_value.as_str()), ("User-Agent", user_agent.as_str())];
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
                    if let Some((bypass, status, body)) = self.check_bypass(args).await {
                        print_fancy_bypass(&bypass, status);
                        if let Err(e) = snapshot::take_snapshot(bypass.bypass_url.clone(), domain.to_string(), bypass.method.clone(), bypass.technique.clone(), body).await {
                            eprintln!("\nFailed to take snapshot for {}: {}", &bypass.bypass_url, e);
                        }
                        return Some(bypass);
                    }
                }
            }
        }
        None
    }

    fn generate_bypass_techniques(&self, original_url: &Url, directory: &str) -> Vec<(Url, String)> {
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
            "TRACE" => args.client.request(reqwest::Method::TRACE, args.technique_url.clone()),
            "OPTIONS" => args.client.request(reqwest::Method::OPTIONS, args.technique_url.clone()),
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
    println!("{} {} {}", "Status Code :".cyan(), status.to_string().green(), "OK".green());
}
