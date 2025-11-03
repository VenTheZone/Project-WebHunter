use crate::form::Form;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct SqlInjectionVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
}

use std::fs;
use std::io::{self, BufRead};

pub struct SqlInjectionScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    error_based_payloads: Vec<String>,
    boolean_based_payloads: Vec<(String, String)>,
    time_based_payloads: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> SqlInjectionScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let mut error_based_payloads = Self::load_payloads("webhunter/wordlists/sql_injection/error_based.txt");
        error_based_payloads.extend(Self::load_payloads("webhunter/wordlists/sql_injection/original_payloads.txt"));
        let boolean_based_payloads = Self::load_boolean_payloads("webhunter/wordlists/sql_injection/boolean_based.txt");
        let time_based_payloads = Self::load_payloads("webhunter/wordlists/sql_injection/time_based.txt");

        Self {
            target_urls,
            forms,
            error_based_payloads,
            boolean_based_payloads,
            time_based_payloads,
            reporter,
            rate_limiter,
        }
    }

    fn load_payloads(path: &str) -> Vec<String> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                payloads.push(line);
            }
        }
        payloads
    }

    fn load_boolean_payloads(path: &str) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.split("/").collect();
                if parts.len() == 2 {
                    payloads.push((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }
        payloads
    }

    pub fn payloads_count(&self) -> usize {
        self.error_based_payloads.len()
            + self.boolean_based_payloads.len() * 2
            + self.time_based_payloads.len()
    }

    pub async fn scan(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;
        Ok(())
    }

    async fn scan_urls(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            for i in 0..query_pairs.len() {
                let mut vulnerable = false;
                for payload in &self.error_based_payloads {
                    if self.test_error_based(&client, url, payload, i, pb).await? {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable { continue; }

                for (true_payload, false_payload) in &self.boolean_based_payloads {
                     if self.test_boolean_based(&client, url, true_payload, false_payload, i, pb).await? {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable { continue; }

                for payload in &self.time_based_payloads {
                    if self.test_time_based(&client, url, payload, i, pb).await? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn test_boolean_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        true_payload: &str,
        false_payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        let mut true_query_parts = Vec::new();
        let mut false_query_parts = Vec::new();
        let mut tested_param = String::new();

        for (j, (key, value)) in query_pairs.iter().enumerate() {
            if param_index == j {
                true_query_parts.push(format!("{}={}{}", key, value, true_payload));
                false_query_parts.push(format!("{}={}{}", key, value, false_payload));
                tested_param = key.clone();
            } else {
                true_query_parts.push(format!("{}={}", key, value));
                false_query_parts.push(format!("{}={}", key, value));
            }
        }

        let true_query = true_query_parts.join("&");
        let false_query = false_query_parts.join("&");

        let mut true_url = url.clone();
        true_url.set_query(Some(&true_query));

        let mut false_url = url.clone();
        false_url.set_query(Some(&false_query));

        self.rate_limiter.wait().await;
        if let (Some(true_response), Some(false_response)) = (
            self.send_get_request(client, &true_url).await,
            self.send_get_request(client, &false_url).await,
        ) {
            if let (Ok(true_body), Ok(false_body)) =
                (true_response.text().await, false_response.text().await)
            {
                if true_body != false_body {
                    let vuln = SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param.clone(),
                        payload: format!("{} / {}", true_payload, false_payload),
                        vuln_type: "Boolean-Based".to_string(),
                    };
                    println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
                    self.reporter.report_sql_injection(&vuln);
                    return Ok(true);
                }
            }
        }
        pb.inc(2);
        Ok(false)
    }

    async fn test_time_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        let mut new_query_parts = Vec::new();
        let mut tested_param = String::new();

        for (j, (key, value)) in query_pairs.iter().enumerate() {
            if param_index == j {
                new_query_parts.push(format!("{}={}{}", key, value, payload));
                tested_param = key.clone();
            } else {
                new_query_parts.push(format!("{}={}", key, value));
            }
        }

        let new_query = new_query_parts.join("&");
        let mut new_url = url.clone();
        new_url.set_query(Some(&new_query));

        let start = Instant::now();
        self.rate_limiter.wait().await;
        if self.send_get_request(client, &new_url).await.is_some() {
            let duration = start.elapsed();
            if duration > Duration::from_secs(2) {
                let vuln = SqlInjectionVulnerability {
                    url: url.clone(),
                    parameter: tested_param.clone(),
                    payload: payload.to_string(),
                    vuln_type: "Time-Based".to_string(),
                };
                println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
                self.reporter.report_sql_injection(&vuln);
                return Ok(true);
            }
        }
        pb.inc(1);
        Ok(false)
    }

    async fn scan_forms(
        &self,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for form in &self.forms {
            for i in 0..form.inputs.len() {
                let mut vulnerable = false;
                for payload in &self.error_based_payloads {
                    if self.test_form_error_based(&client, form, payload, i, pb).await? {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable { continue; }

                for (true_payload, false_payload) in &self.boolean_based_payloads {
                    if self.test_form_boolean_based(&client, form, true_payload, false_payload, i, pb).await? {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable { continue; }

                for payload in &self.time_based_payloads {
                    if self.test_form_time_based(&client, form, payload, i, pb).await? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn test_form_error_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let mut form_data = HashMap::new();
        let mut tested_param = String::new();
        for (j, input) in form.inputs.iter().enumerate() {
            if param_index == j {
                form_data.insert(input.name.clone(), payload.to_string());
                tested_param = input.name.clone();
            } else {
                form_data.insert(input.name.clone(), input.value.clone());
            }
        }

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        self.rate_limiter.wait().await;
        let response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&form_data).send().await?
        } else {
            client.get(action_url).query(&form_data).send().await?
        };

        pb.inc(1);
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if let Ok(body) = response.text().await {
            if self.is_error_based_vulnerable(&body) {
                let vuln = SqlInjectionVulnerability {
                    url: form.url.clone(),
                    parameter: tested_param.clone(),
                    payload: payload.to_string(),
                    vuln_type: "Error-Based".to_string(),
                };
                println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
                self.reporter.report_sql_injection(&vuln);
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn test_form_boolean_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        true_payload: &str,
        false_payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let mut true_form_data = HashMap::new();
        let mut false_form_data = HashMap::new();
        let mut tested_param = String::new();
        for (j, input) in form.inputs.iter().enumerate() {
            if param_index == j {
                true_form_data.insert(input.name.clone(), true_payload.to_string());
                false_form_data.insert(input.name.clone(), false_payload.to_string());
                tested_param = input.name.clone();
            } else {
                true_form_data.insert(input.name.clone(), input.value.clone());
                false_form_data.insert(input.name.clone(), input.value.clone());
            }
        }

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        self.rate_limiter.wait().await;
        let true_response = if form.method.to_lowercase() == "post" {
            client
                .post(action_url.clone())
                .form(&true_form_data)
                .send()
                .await?
        } else {
            client
                .get(action_url.clone())
                .query(&true_form_data)
                .send()
                .await?
        };

        if true_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        self.rate_limiter.wait().await;
        let false_response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&false_form_data).send().await?
        } else {
            client.get(action_url).query(&false_form_data).send().await?
        };

        pb.inc(2);
        if false_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if let (Ok(true_body), Ok(false_body)) = (true_response.text().await, false_response.text().await) {
            if true_body != false_body {
                let vuln = SqlInjectionVulnerability {
                    url: form.url.clone(),
                    parameter: tested_param.clone(),
                    payload: format!("{} / {}", true_payload, false_payload),
                    vuln_type: "Boolean-Based".to_string(),
                };
                println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
                self.reporter.report_sql_injection(&vuln);
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn test_form_time_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let mut form_data = HashMap::new();
        let mut tested_param = String::new();
        for (j, input) in form.inputs.iter().enumerate() {
            if param_index == j {
                form_data.insert(input.name.clone(), payload.to_string());
                tested_param = input.name.clone();
            } else {
                form_data.insert(input.name.clone(), input.value.clone());
            }
        }

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        let start = Instant::now();
        self.rate_limiter.wait().await;
        let response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&form_data).send().await?
        } else {
            client.get(action_url).query(&form_data).send().await?
        };
        let duration = start.elapsed();

        pb.inc(1);
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if duration > Duration::from_secs(5) {
            let vuln = SqlInjectionVulnerability {
                url: form.url.clone(),
                parameter: tested_param.clone(),
                payload: payload.to_string(),
                vuln_type: "Time-Based".to_string(),
            };
            println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
            self.reporter.report_sql_injection(&vuln);
            return Ok(true);
        }
        Ok(false)
    }

    async fn test_error_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

        let mut new_query_parts = Vec::new();
        let mut tested_param = String::new();

        for (j, (key, value)) in query_pairs.iter().enumerate() {
            if param_index == j {
                new_query_parts.push(format!("{}={}{}", key, value, payload));
                tested_param = key.clone();
            } else {
                new_query_parts.push(format!("{}={}", key, value));
            }
        }

        let new_query = new_query_parts.join("&");
        let mut new_url = url.clone();
        new_url.set_query(Some(&new_query));

        self.rate_limiter.wait().await;
        if let Some(response) = self.send_get_request(client, &new_url).await {
            if let Ok(body) = response.text().await {
                if self.is_error_based_vulnerable(&body) {
                    let vuln = SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param.clone(),
                        payload: payload.to_string(),
                        vuln_type: "Error-Based".to_string(),
                    };
                    println!("[+] SQL Injection Found: {} in {}", vuln.payload, vuln.parameter);
                    self.reporter.report_sql_injection(&vuln);
                    return Ok(true);
                }
            }
        }
        pb.inc(1);
        Ok(false)
    }

    async fn send_get_request(&self, client: &reqwest::Client, url: &Url) -> Option<reqwest::Response> {
        match client.get(url.clone()).send().await {
            Ok(response) => {
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return None;
                }
                Some(response)
            }
            Err(e) => {
                eprintln!("[!] Error sending GET request to {}: {}", url, e);
                None
            }
        }
    }

    fn is_error_based_vulnerable(&self, body: &str) -> bool {
        let error_patterns = [
            // MySQL
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            // MSSQL
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",
            // Oracle
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            // PostgreSQL
            "ERROR: unterminated quoted string at or near",
            "ERROR: syntax error at or near",
            // SQLite
            "SQLite/JDBCDriver",
            "SQLITE_ERROR",
        ];
        error_patterns.iter().any(|&p| body.contains(p))
    }
}
