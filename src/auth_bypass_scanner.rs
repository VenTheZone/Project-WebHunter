use crate::form::Form;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthBypassVulnerability {
    pub url: Url,
    pub form_action: String,
    pub payload: String,
    pub vuln_type: String,
    pub description: String,
}

pub struct AuthBypassScanner<'a> {
    forms: Vec<Form>,
    sqli_payloads: Vec<String>,
    default_creds: Vec<(String, String)>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> AuthBypassScanner<'a> {
    pub fn new(
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let sqli_payloads =
            Self::load_list("webhunter/wordlists/auth_bypass/sqli_login_bypass.txt");
        let default_creds = Self::load_creds("webhunter/wordlists/auth_bypass/default_creds.txt");

        Self {
            forms,
            sqli_payloads,
            default_creds,
            reporter,
            rate_limiter,
        }
    }

    fn load_list(path: &str) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    list.push(line);
                }
            }
        }
        list
    }

    fn load_creds(path: &str) -> Vec<(String, String)> {
        let mut list = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Some((user, pass)) = line.split_once(':') {
                    list.push((user.trim().to_string(), pass.trim().to_string()));
                }
            }
        }
        list
    }

    pub fn payloads_count(&self) -> usize {
        let mut count = 0;
        for form in &self.forms {
            if self.is_login_form(form) {
                count += self.sqli_payloads.len() + self.default_creds.len();
            }
        }
        count
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // We want to detect redirects manually
            .build()?;

        for form in &self.forms {
            if self.is_login_form(form) {
                self.test_sqli_bypass(form, &client, pb).await?;
                self.test_default_creds(form, &client, pb).await?;
            }
        }
        Ok(())
    }

    fn is_login_form(&self, form: &Form) -> bool {
        let input_names: Vec<String> = form.inputs.iter().map(|i| i.name.to_lowercase()).collect();
        let has_user = input_names.iter().any(|n| {
            n.contains("user") || n.contains("email") || n.contains("login") || n.contains("id")
        });
        let has_pass = input_names
            .iter()
            .any(|n| n.contains("pass") || n.contains("pwd") || n.contains("key"));

        // Also check if it's a password type input
        let has_password_type = form.inputs.iter().any(|i| i.input_type == "password");

        (has_user && has_pass) || has_password_type
    }

    async fn test_sqli_bypass(
        &self,
        form: &Form,
        client: &reqwest::Client,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        let action_url = form.url.join(&form.action).unwrap_or(form.url.clone());

        for payload in &self.sqli_payloads {
            let mut form_data = HashMap::new();

            for input in &form.inputs {
                let name_lower = input.name.to_lowercase();
                if name_lower.contains("user")
                    || name_lower.contains("email")
                    || name_lower.contains("login")
                {
                    form_data.insert(input.name.clone(), payload.clone());
                } else if name_lower.contains("pass") {
                    form_data.insert(input.name.clone(), "password123".to_string());
                // Dummy password
                } else {
                    form_data.insert(input.name.clone(), input.value.clone());
                }
            }

            self.rate_limiter.wait().await;
            let response = if form.method.to_lowercase() == "post" {
                client
                    .post(action_url.clone())
                    .form(&form_data)
                    .send()
                    .await?
            } else {
                client
                    .get(action_url.clone())
                    .query(&form_data)
                    .send()
                    .await?
            };
            pb.inc(1);

            if self.check_login_success(response).await {
                let vuln = AuthBypassVulnerability {
                    url: form.url.clone(),
                    form_action: form.action.clone(),
                    payload: payload.clone(),
                    vuln_type: "SQL Injection Login Bypass".to_string(),
                    description:
                        "Successfully bypassed authentication using SQL injection payload."
                            .to_string(),
                };
                println!("[+] Auth Bypass Found: {} in login form", vuln.payload);
                self.reporter.report_auth_bypass(&vuln);
                return Ok(()); // Stop after first success to avoid noise
            }
        }
        Ok(())
    }

    async fn test_default_creds(
        &self,
        form: &Form,
        client: &reqwest::Client,
        pb: &ProgressBar,
    ) -> Result<(), reqwest::Error> {
        let action_url = form.url.join(&form.action).unwrap_or(form.url.clone());

        for (username, password) in &self.default_creds {
            let mut form_data = HashMap::new();

            for input in &form.inputs {
                let name_lower = input.name.to_lowercase();
                if name_lower.contains("user")
                    || name_lower.contains("email")
                    || name_lower.contains("login")
                {
                    form_data.insert(input.name.clone(), username.clone());
                } else if name_lower.contains("pass") {
                    form_data.insert(input.name.clone(), password.clone());
                } else {
                    form_data.insert(input.name.clone(), input.value.clone());
                }
            }

            self.rate_limiter.wait().await;
            let response = if form.method.to_lowercase() == "post" {
                client
                    .post(action_url.clone())
                    .form(&form_data)
                    .send()
                    .await?
            } else {
                client
                    .get(action_url.clone())
                    .query(&form_data)
                    .send()
                    .await?
            };
            pb.inc(1);

            if self.check_login_success(response).await {
                let vuln = AuthBypassVulnerability {
                    url: form.url.clone(),
                    form_action: form.action.clone(),
                    payload: format!("{}:{}", username, password),
                    vuln_type: "Default Credentials".to_string(),
                    description: "Successfully logged in using default credentials.".to_string(),
                };
                println!("[+] Auth Bypass Found: {} (Default Creds)", vuln.payload);
                self.reporter.report_auth_bypass(&vuln);
                return Ok(());
            }
        }
        Ok(())
    }

    async fn check_login_success(&self, response: reqwest::Response) -> bool {
        // Check for redirects (3xx) which often indicate success
        if response.status().is_redirection() {
            if let Some(location) = response.headers().get("Location") {
                let loc_str = location.to_str().unwrap_or("").to_lowercase();
                if loc_str.contains("dashboard")
                    || loc_str.contains("admin")
                    || loc_str.contains("account")
                    || loc_str.contains("home")
                {
                    return true;
                }
                // If it redirects back to login, it's likely a failure
                if loc_str.contains("login") || loc_str.contains("signin") {
                    return false;
                }
            }
            return true; // Assume other redirects might be success
        }

        // Check body content for success indicators
        if let Ok(body) = response.text().await {
            // Note: consumes response body
            let body_lower = body.to_lowercase();
            if (body_lower.contains("welcome")
                || body_lower.contains("dashboard")
                || body_lower.contains("logout")
                || body_lower.contains("sign out"))
                && !body_lower.contains("invalid")
                && !body_lower.contains("failed")
                && !body_lower.contains("incorrect")
            {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_form(inputs: Vec<(&str, &str, &str)>) -> Form {
        let inputs = inputs
            .into_iter()
            .map(|(name, val, type_)| crate::form::FormInput {
                name: name.to_string(),
                value: val.to_string(),
                input_type: type_.to_string(),
            })
            .collect();

        Form {
            url: Url::parse("http://example.com/login").unwrap(),
            action: "/login.php".to_string(),
            method: "POST".to_string(),
            inputs,
        }
    }

    fn create_test_scanner() -> AuthBypassScanner<'static> {
        let reporter = Box::leak(Box::new(Arc::new(Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ))));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_millis(0)));

        AuthBypassScanner::new(vec![], reporter, rate_limiter)
    }

    #[test]
    fn test_is_login_form_detection() {
        let scanner = create_test_scanner();

        // Valid login form (user + pass)
        let form1 = create_test_form(vec![("username", "", "text"), ("password", "", "password")]);
        assert!(scanner.is_login_form(&form1));

        // Valid login form (email + pwd)
        let form2 = create_test_form(vec![("email", "", "email"), ("pwd", "", "password")]);
        assert!(scanner.is_login_form(&form2));

        // Invalid form (search)
        let form3 = create_test_form(vec![("q", "", "text"), ("search", "Search", "submit")]);
        assert!(!scanner.is_login_form(&form3));
    }
}
