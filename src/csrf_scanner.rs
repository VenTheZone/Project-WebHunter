use crate::form::Form;
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use std::sync::Arc;
use url::Url;

/// Common CSRF token field name patterns
const CSRF_TOKEN_PATTERNS: &[&str] = &[
    "csrf",
    "_token",
    "authenticity_token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "_csrf",
    "anti-csrf-token",
    "xsrf",
    "token",
];

#[derive(Debug, Clone)]
pub struct CsrfVulnerability {
    pub url: Url,
    pub form_action: String,
    pub method: String,
    pub missing_protections: Vec<String>,
    pub severity: String,
    pub poc_html: String,
}

pub struct CsrfScanner<'a> {
    forms: Vec<Form>,
    _endpoints: Vec<Url>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> CsrfScanner<'a> {
    pub fn new(
        forms: Vec<Form>,
        endpoints: Vec<Url>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            forms,
            _endpoints: endpoints,
            reporter,
            rate_limiter,
        }
    }

    pub async fn scan(&self) -> Result<(), reqwest::Error> {
        println!("Starting CSRF scan on {} forms...", self.forms.len());

        for form in &self.forms {
            self.rate_limiter.wait().await;

            if !self.has_csrf_token(form) {
                let missing_protections = vec!["CSRF Token".to_string()];

                // Check for SameSite cookies (would require response headers)
                // For now, we mark it as a potential issue

                let action_url = form
                    .url
                    .join(&form.action)
                    .unwrap_or_else(|_| form.url.clone());

                let vuln = CsrfVulnerability {
                    url: form.url.clone(),
                    form_action: action_url.to_string(),
                    method: form.method.clone(),
                    missing_protections: missing_protections.clone(),
                    severity: self.calculate_severity(&missing_protections),
                    poc_html: self.generate_poc(form),
                };

                println!(
                    "[+] CSRF Vulnerability: {} ({} - missing: {})",
                    vuln.form_action,
                    vuln.method,
                    vuln.missing_protections.join(", ")
                );

                self.reporter.report_csrf(&vuln);
            }
        }

        Ok(())
    }

    /// Check if a form has CSRF token protection
    fn has_csrf_token(&self, form: &Form) -> bool {
        for input in &form.inputs {
            let name_lower = input.name.to_lowercase();

            // Check if input name contains any CSRF token pattern
            for pattern in CSRF_TOKEN_PATTERNS {
                if name_lower.contains(pattern) {
                    // Also check if it has a non-empty value (token is set)
                    if !input.value.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Calculate severity based on missing protections
    fn calculate_severity(&self, missing_protections: &[String]) -> String {
        if missing_protections.len() >= 2 {
            "High".to_string()
        } else {
            "Medium".to_string()
        }
    }

    /// Generate proof-of-concept HTML for CSRF exploitation
    fn generate_poc(&self, form: &Form) -> String {
        let action_url = form
            .url
            .join(&form.action)
            .unwrap_or_else(|_| form.url.clone());
        let method = form.method.to_uppercase();

        let mut inputs_html = String::new();
        for input in &form.inputs {
            // Use basic escaping for demonstration
            let name = input.name.replace('"', "&quot;");
            let value = input.value.replace('"', "&quot;");

            inputs_html.push_str(&format!(
                "    <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
                name, value
            ));
        }

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page will automatically submit the form on load.</p>
    <p>Target: {}</p>
    
    <form id="csrfForm" action="{}" method="{}">
{}
        <input type="submit" value="Submit" />
    </form>
    
    <script>
        // Auto-submit on page load
        window.onload = function() {{
            document.getElementById('csrfForm').submit();
        }};
    </script>
</body>
</html>"#,
            action_url, action_url, action_url, method, inputs_html
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::form::FormInput;
    use std::time::Duration;

    fn create_test_form(inputs: Vec<FormInput>) -> Form {
        Form {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs,
            url: Url::parse("https://example.com/form").unwrap(),
        }
    }

    fn create_test_scanner() -> CsrfScanner<'static> {
        let reporter = Box::leak(Box::new(Arc::new(Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ))));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_millis(0)));

        CsrfScanner::new(vec![], vec![], reporter, rate_limiter)
    }

    #[test]
    fn test_has_csrf_token_with_csrf_token() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![
            FormInput {
                name: "username".to_string(),
                value: "test".to_string(),
                input_type: "text".to_string(),
            },
            FormInput {
                name: "csrf_token".to_string(),
                value: "abc123xyz".to_string(),
                input_type: "hidden".to_string(),
            },
        ]);

        assert!(scanner.has_csrf_token(&form), "Should detect CSRF token");
    }

    #[test]
    fn test_has_csrf_token_with_authenticity_token() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![FormInput {
            name: "authenticity_token".to_string(),
            value: "secure_token_123".to_string(),
            input_type: "hidden".to_string(),
        }]);

        assert!(
            scanner.has_csrf_token(&form),
            "Should detect authenticity_token"
        );
    }

    #[test]
    fn test_has_csrf_token_case_insensitive() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![FormInput {
            name: "CSRF_TOKEN".to_string(),
            value: "token123".to_string(),
            input_type: "hidden".to_string(),
        }]);

        assert!(
            scanner.has_csrf_token(&form),
            "Should detect CSRF token (case insensitive)"
        );
    }

    #[test]
    fn test_has_csrf_token_empty_value() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![FormInput {
            name: "csrf_token".to_string(),
            value: "".to_string(), // Empty value - not a valid token
            input_type: "hidden".to_string(),
        }]);

        assert!(
            !scanner.has_csrf_token(&form),
            "Should not detect empty CSRF token"
        );
    }

    #[test]
    fn test_has_csrf_token_without_token() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![
            FormInput {
                name: "username".to_string(),
                value: "test".to_string(),
                input_type: "text".to_string(),
            },
            FormInput {
                name: "password".to_string(),
                value: "secret".to_string(),
                input_type: "password".to_string(),
            },
        ]);

        assert!(
            !scanner.has_csrf_token(&form),
            "Should not detect CSRF token when missing"
        );
    }

    #[test]
    fn test_generate_poc() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![
            FormInput {
                name: "email".to_string(),
                value: "victim@example.com".to_string(),
                input_type: "email".to_string(),
            },
            FormInput {
                name: "amount".to_string(),
                value: "1000".to_string(),
                input_type: "number".to_string(),
            },
        ]);

        let poc = scanner.generate_poc(&form);

        // Verify PoC contains essential elements
        assert!(poc.contains("<form"), "PoC should contain form tag");
        assert!(
            poc.contains("method=\"POST\""),
            "PoC should have POST method"
        );
        assert!(
            poc.contains("https://example.com/submit"),
            "PoC should have action URL"
        );
        assert!(
            poc.contains("name=\"email\""),
            "PoC should include email input"
        );
        assert!(
            poc.contains("name=\"amount\""),
            "PoC should include amount input"
        );
        assert!(
            poc.contains("value=\"victim@example.com\""),
            "PoC should have email value"
        );
        assert!(
            poc.contains("value=\"1000\""),
            "PoC should have amount value"
        );
        assert!(
            poc.contains("window.onload"),
            "PoC should have auto-submit script"
        );
        assert!(poc.contains(".submit()"), "PoC should call submit()");
    }

    #[test]
    fn test_calculate_severity() {
        let scanner = create_test_scanner();

        let missing_one = vec!["CSRF Token".to_string()];
        assert_eq!(scanner.calculate_severity(&missing_one), "Medium");

        let missing_two = vec!["CSRF Token".to_string(), "SameSite Cookie".to_string()];
        assert_eq!(scanner.calculate_severity(&missing_two), "High");
    }

    #[test]
    fn test_poc_escapes_quotes() {
        let scanner = create_test_scanner();
        let form = create_test_form(vec![FormInput {
            name: "text".to_string(),
            value: "value with \"quotes\"".to_string(),
            input_type: "text".to_string(),
        }]);

        let poc = scanner.generate_poc(&form);
        assert!(poc.contains("&quot;"), "PoC should escape quotes");
    }
}
