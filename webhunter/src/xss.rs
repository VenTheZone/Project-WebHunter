use crate::form::Form;
use html_escape;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub proof_of_concept: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
    pub severity: String,
    pub method: String,
    pub technique: String,
}

pub struct XssScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    payloads: HashMap<String, Vec<String>>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

use std::fs;
use std::io::{self, BufRead};

impl<'a> XssScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let mut payloads = HashMap::new();
        if let Ok(paths) = fs::read_dir("webhunter/wordlists/xss") {
            for path in paths.flatten() {
                if let Some(extension) = path.path().extension() {
                    if extension == "txt" {
                        if let Ok(file) = fs::File::open(path.path()) {
                            let reader = io::BufReader::new(file);
                            let technique = path
                                .path()
                                .file_stem()
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_string();
                            let mut technique_payloads = Vec::new();
                            for line in reader.lines().map_while(Result::ok) {
                                technique_payloads.push(line);
                            }
                            payloads.insert(technique, technique_payloads);
                        }
                    }
                }
            }
        }

        Self {
            target_urls,
            forms,
            payloads,
            reporter,
            rate_limiter,
        }
    }

    pub fn payloads_count(&self) -> usize {
        self.payloads.values().map(|p| p.len()).sum()
    }

    pub async fn scan(&self) -> Result<(), reqwest::Error> {
        self.scan_urls().await?;
        self.scan_forms().await?;
        Ok(())
    }

    async fn scan_urls(&self) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            'param_loop: for i in 0..query_pairs.len() {
                for (technique, payloads) in &self.payloads {
                    for payload in payloads {
                        let mut new_query_parts = Vec::new();
                        let mut tested_param = String::new();
                    for (j, (key, value)) in query_pairs.iter().enumerate() {
                        if i == j {
                            new_query_parts.push(format!("{}={}", key, payload));
                            tested_param = key.clone();
                        } else {
                            new_query_parts.push(format!("{}={}", key, value));
                        }
                    }
                    let new_query = new_query_parts.join("&");
                    let mut new_url = url.clone();
                    new_url.set_query(Some(&new_query));

                    self.rate_limiter.wait().await;
                    let response = client.get(new_url.clone()).send().await?;
                    if response.status() == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }
                    if let Ok(body) = response.text().await {
                        if self.is_vulnerable(&body, payload) {
                            let vuln = Vulnerability {
                                proof_of_concept: new_url.clone(),
                                parameter: tested_param.clone(),
                                payload: payload.clone(),
                                vuln_type: "Reflected".to_string(),
                                severity: "Medium".to_string(),
                                method: "GET".to_string(),
                                technique: technique.clone(),
                            };
                            println!("[+] XSS Found: {} in {}", vuln.payload, vuln.parameter);
                            self.reporter.report_xss(&vuln);
                            continue 'param_loop;
                        }
                    }
                    }
                }
            }
        }
        Ok(())
    }

    async fn scan_forms(&self) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::new();

        for form in &self.forms {
            'input_loop: for i in 0..form.inputs.len() {
                for (technique, payloads) in &self.payloads {
                    for payload in payloads {
                        let mut form_data = HashMap::new();
                        let mut tested_param = String::new();
                    for (j, input) in form.inputs.iter().enumerate() {
                        if i == j {
                            form_data.insert(input.name.clone(), payload.clone());
                            tested_param = input.name.clone();
                        } else {
                            form_data.insert(input.name.clone(), input.value.clone());
                        }
                    }

                    let base_action_url = match form.url.join(&form.action) {
                        Ok(url) => url,
                        Err(_) => continue,
                    };

                    let response_res;
                    let poc_url;

                    self.rate_limiter.wait().await;
                    if form.method.to_lowercase() == "post" {
                        poc_url = base_action_url.clone();
                        let original_query =
                            base_action_url.query_pairs().into_owned().collect::<Vec<(String, String)>>();
                        let mut post_form_data = form_data.clone();
                        for (key, value) in original_query {
                            post_form_data.insert(key, value);
                        }
                        response_res = client
                            .post(base_action_url.clone())
                            .form(&post_form_data)
                            .send()
                            .await;
                    } else {
                        // GET
                        let mut full_url = base_action_url.clone();
                        for (key, value) in form_data.iter() {
                            full_url.query_pairs_mut().append_pair(key, value);
                        }
                        poc_url = full_url;
                        response_res = client.get(poc_url.clone()).send().await;
                    };

                    if let Ok(response) = response_res {
                        if response.status() == reqwest::StatusCode::NOT_FOUND {
                            continue;
                        }
                        if let Ok(body) = response.text().await {
                            if self.is_vulnerable(&body, payload) {
                                let vuln = Vulnerability {
                                    proof_of_concept: poc_url.clone(),
                                    parameter: tested_param.clone(),
                                    payload: payload.clone(),
                                    vuln_type: "Reflected".to_string(),
                                    severity: "Medium".to_string(),
                                    method: form.method.to_string(),
                                    technique: technique.clone(),
                                };
                                println!("[+] XSS Found: {} in {}", vuln.payload, vuln.parameter);
                                self.reporter.report_xss(&vuln);
                                continue 'input_loop;
                            }
                        }
                    }
                    }
                }
            }
        }
        Ok(())
    }

    fn is_vulnerable(&self, body: &str, payload: &str) -> bool {
        let decoded_body = html_escape::decode_html_entities(body);
        let document = Html::parse_document(&decoded_body);
        let script_selector = Selector::parse("script").unwrap();
        for element in document.select(&script_selector) {
            if element.inner_html().contains(payload) {
                return true;
            }
        }

        let event_handler_attributes = [
            "onload",
            "onerror",
            "onmouseover",
            "onclick",
            "onmousedown",
            "onmouseup",
            "onmousemove",
            "onmouseout",
            "onkeydown",
            "onkeyup",
            "onkeypress",
            "onfocus",
            "onblur",
            "onsubmit",
            "onreset",
            "onchange",
            "onselect",
        ];

        for attr in &event_handler_attributes {
            let selector_str = format!("[{}]", attr);
            let selector = Selector::parse(&selector_str).unwrap();
            for element in document.select(&selector) {
                if let Some(attr_value) = element.value().attr(attr) {
                    let decoded_attr = html_escape::decode_html_entities(attr_value);
                    if decoded_attr.contains(payload) {
                        return true;
                    }
                }
            }
        }

        false
    }
}
