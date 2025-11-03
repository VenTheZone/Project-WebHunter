# XSS Scanner Module - Pseudo-Code
## File: xss.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - scraper (HTML parsing)
    - tokio (async runtime)
    - indicatif (progress tracking)

IMPORT modules:
    - form (Form structure)
    - rate_limiter (RateLimiter structure)
    - reporter (Reporter structure)

STRUCTURE Vulnerability:
    FIELDS:
        proof_of_concept: Url
        parameter: String
        payload: String
        vuln_type: String
        severity: String
        method: String

STRUCTURE XssScanner:
    FIELDS:
        target_urls: Vector<Url>
        forms: Vector<Form>
        payloads: Vector<String>
        reporter: &Arc<Reporter>
        rate_limiter: Arc<RateLimiter>

FUNCTION XssScanner::new(target_urls, forms, reporter, rate_limiter):
    DESCRIPTION: Creates a new XssScanner instance.
    PROCESS:
        LOAD payloads from "webhunter/wordlists/xss/**/*.txt"
        INITIALIZE and return XssScanner instance

FUNCTION XssScanner::payloads_count() -> usize:
    RETURNS the number of loaded payloads.

ASYNC FUNCTION XssScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for XSS vulnerabilities.
    PROCESS:
        CALL scan_urls(progress_bar)
        CALL scan_forms(progress_bar)
        RETURN Ok

ASYNC FUNCTION XssScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for reflected XSS.
    PROCESS:
        FOR each url in target_urls:
            IF url has no query parameters, CONTINUE
            FOR i in 0..query_pairs.len():
                FOR each payload in payloads:
                    BUILD new_url with payload injected into the i-th parameter
                    AWAIT rate_limiter.wait()
                    SEND GET request to new_url
                    INCREMENT progress_bar
                    IF response status is not 404:
                        IF is_vulnerable(body, payload):
                            CREATE Vulnerability
                            PRINT confirmation message
                            CALL reporter.report_xss(&vuln)
                            CONTINUE to next parameter loop

ASYNC FUNCTION XssScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for reflected XSS.
    PROCESS:
        FOR each form in forms:
            FOR i in 0..form.inputs.len():
                FOR each payload in payloads:
                    BUILD form_data with payload injected into the i-th input
                    CONSTRUCT action_url
                    AWAIT rate_limiter.wait()
                    IF form.method is POST:
                        SEND POST request
                    ELSE:
                        SEND GET request
                    INCREMENT progress_bar
                    IF response is Ok and status is not 404:
                        IF is_vulnerable(body, payload):
                            CREATE Vulnerability
                            PRINT confirmation message
                            CALL reporter.report_xss(&vuln)
                            CONTINUE to next input loop

FUNCTION XssScanner::is_vulnerable(body, payload) -> bool:
    DESCRIPTION: Checks if the payload is reflected in the response body in a way that could trigger XSS.
    PROCESS:
        PARSE body as HTML
        CHECK for payload inside <script> tags
        CHECK for payload in event handler attributes (e.g., onload, onerror)
        RETURN true if found, otherwise false
```

## XSS Detection Logic

```pseudo
DETECTION_METHODS:
    1. Script Tag Injection:
       - Checks if the payload is found within the inner HTML of a <script> tag.
    2. Event Handler Injection:
       - Checks if the payload is present in common event handler attributes like `onload`, `onerror`, etc.

VULNERABILITY_TYPES:
    - Reflected XSS: The scanner primarily looks for reflected vulnerabilities where the payload is immediately returned in the response.

PAYLOAD_SOURCES:
    - Location: webhunter/wordlists/xss/*.txt
```

## Testing Strategy

```pseudo
TESTING_APPROACH:
    - For URLs: Iterates through each URL parameter, injecting one payload at a time.
    - For Forms: Iterates through each form input, injecting one payload at a time.
    - Optimization: Once a vulnerability is found for a specific parameter or input, it moves to the next one.

RATE_LIMITING:
    - Uses a shared RateLimiter to control the request frequency.
```