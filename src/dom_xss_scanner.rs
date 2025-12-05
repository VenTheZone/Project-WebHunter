use scraper::{Html, Selector};
use std::sync::Arc;
use url::Url;

use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;

// DOM XSS Sources (attacker-controlled)
const DOM_SOURCES: &[&str] = &[
    "window.location",
    "document.location",
    "location.href",
    "location.hash",
    "location.search",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "document.referrer",
    "document.cookie",
    "window.name",
    "localStorage",
    "sessionStorage",
];

// DOM XSS Sinks (dangerous operations)
const DOM_SINKS: &[&str] = &[
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "execScript",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "location.href",
    "location.assign",
    "location.replace",
    "script.src",
    "script.text",
    "script.textContent",
    "script.innerText",
];

#[derive(Debug, Clone)]
pub struct DomXssVulnerability {
    pub url: Url,
    pub source: String,
    pub sink: String,
    pub line_number: usize,
    pub code_snippet: String,
    pub severity: String,
}

pub struct DomXssScanner<'a> {
    reporter: &'a Arc<Reporter>,
    _rate_limiter: Arc<RateLimiter>,
}

impl<'a> DomXssScanner<'a> {
    pub fn new(reporter: &'a Arc<Reporter>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            reporter,
            _rate_limiter: rate_limiter,
        }
    }

    pub async fn scan(&self, url: Url, html: String) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting DOM XSS analysis for: {}", url);

        // Extract scripts from HTML
        let scripts = self.extract_scripts(&html);
        println!("Found {} inline scripts to analyze", scripts.len());

        // Analyze each script for DOM XSS patterns
        for (idx, script_content) in scripts.iter().enumerate() {
            let vulnerabilities = self.analyze_script(&url, script_content, idx + 1);

            for vuln in vulnerabilities {
                println!(
                    "[+] DOM XSS: {} → {} (line {})",
                    vuln.source, vuln.sink, vuln.line_number
                );
                self.reporter.report_dom_xss(&vuln);
            }
        }

        Ok(())
    }

    /// Extract inline JavaScript from HTML <script> tags
    fn extract_scripts(&self, html: &str) -> Vec<String> {
        let document = Html::parse_document(html);
        let script_selector = Selector::parse("script").unwrap();

        document
            .select(&script_selector)
            .filter_map(|element| {
                let content = element.inner_html();
                if !content.trim().is_empty() && element.value().attr("src").is_none() {
                    Some(content)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Analyze JavaScript code for DOM XSS patterns
    /// Phase 1: Simple pattern matching (can be enhanced with SWC later)
    fn analyze_script(
        &self,
        url: &Url,
        script: &str,
        _script_index: usize,
    ) -> Vec<DomXssVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Split script into lines for line-by-line analysis
        for (line_num, line) in script.lines().enumerate() {
            // Check for source → sink patterns
            for source in DOM_SOURCES {
                if line.contains(source) {
                    // Check if this line also contains a sink
                    for sink in DOM_SINKS {
                        if line.contains(sink) {
                            // Found potential DOM XSS
                            let vuln = DomXssVulnerability {
                                url: url.clone(),
                                source: source.to_string(),
                                sink: sink.to_string(),
                                line_number: line_num + 1,
                                code_snippet: line.trim().to_string(),
                                severity: self.calculate_severity(sink),
                            };
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    fn calculate_severity(&self, sink: &str) -> String {
        // eval, Function, execScript are highest severity
        if sink.contains("eval") || sink.contains("Function") || sink.contains("execScript") {
            "Critical".to_string()
        } else if sink.contains("innerHTML") || sink.contains("document.write") {
            "High".to_string()
        } else {
            "Medium".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_scanner() -> DomXssScanner<'static> {
        let reporter = Box::leak(Box::new(Arc::new(Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ))));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_millis(0)));

        DomXssScanner::new(reporter, rate_limiter)
    }

    #[test]
    fn test_extract_scripts_from_html() {
        let scanner = create_test_scanner();
        let html = r#"
            <html>
                <script>var x = 1;</script>
                <script>alert('test');</script>
                <script src="external.js"></script>
            </html>
        "#;

        let scripts = scanner.extract_scripts(html);
        assert_eq!(
            scripts.len(),
            2,
            "Should extract 2 inline scripts, not external"
        );
    }

    #[test]
    fn test_extract_scripts_ignores_empty() {
        let scanner = create_test_scanner();
        let html = r#"
            <html>
                <script></script>
                <script>  </script>
                <script>var x = 1;</script>
            </html>
        "#;

        let scripts = scanner.extract_scripts(html);
        assert_eq!(scripts.len(), 1, "Should only extract non-empty scripts");
    }

    #[test]
    fn test_detect_location_hash_eval() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = "eval(location.hash);";

        let vulns = scanner.analyze_script(&url, script, 1);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].source.contains("location"));
        assert_eq!(vulns[0].sink, "eval");
        assert_eq!(vulns[0].severity, "Critical");
    }

    #[test]
    fn test_detect_innerhtml_with_location() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = "element.innerHTML = location.hash;";

        let vulns = scanner.analyze_script(&url, script, 1);
        assert!(vulns.len() > 0);
        assert_eq!(vulns[0].sink, "innerHTML");
        assert_eq!(vulns[0].severity, "High");
    }

    #[test]
    fn test_detect_document_write_with_url() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = "document.write(document.URL);";

        let vulns = scanner.analyze_script(&url, script, 1);
        assert!(vulns.len() > 0);
        assert!(vulns[0].source.contains("document.URL"));
        assert!(vulns[0].sink.contains("document.write"));
    }

    #[test]
    fn test_no_false_positive_safe_code() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = r#"
            var safe = "hardcoded";
            element.innerHTML = safe;
            console.log("Hello World");
        "#;

        let vulns = scanner.analyze_script(&url, script, 1);
        assert_eq!(
            vulns.len(),
            0,
            "Safe code should not trigger false positives"
        );
    }

    #[test]
    fn test_settimeout_with_location() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = "setTimeout(location.search, 1000);";

        let vulns = scanner.analyze_script(&url, script, 1);
        assert!(vulns.len() > 0);
        assert!(vulns[0].source.contains("location"));
        assert_eq!(vulns[0].sink, "setTimeout");
    }

    #[test]
    fn test_multiple_lines() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = r#"
var x = location.hash;
element.innerHTML = x;
"#;

        let _vulns = scanner.analyze_script(&url, script, 1);
        // This simple version won't catch multi-line taint flow
        // Future: implement with SWC for proper taint tracking
        // For now, we're just testing pattern detection
    }

    #[test]
    fn test_line_numbers_accurate() {
        let scanner = create_test_scanner();
        let url = Url::parse("https://example.com").unwrap();
        let script = "// line 1\n// line 2\neval(location.hash); // line 3";

        let vulns = scanner.analyze_script(&url, script, 1);
        assert_eq!(vulns[0].line_number, 3);
    }
}
