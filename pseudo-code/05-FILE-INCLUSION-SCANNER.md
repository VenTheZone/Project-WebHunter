# File Inclusion Scanner Module - Pseudo-Code
## File: file_inclusion_scanner.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - tokio (async runtime)
    - indicatif (progress tracking)

IMPORT modules:
    - form (Form structure)
    - rate_limiter (RateLimiter structure)
    - reporter (Reporter structure)

STRUCTURE FileInclusionVulnerability:
    FIELDS:
        url: Url
        parameter: String
        payload: String
        vuln_type: String

STRUCTURE FileInclusionScanner:
    FIELDS:
        target_urls: Vector<Url>
        forms: Vector<Form>
        payloads: Vector<String>
        reporter: &Arc<Reporter>
        rate_limiter: Arc<RateLimiter>

FUNCTION FileInclusionScanner::new(target_urls, forms, reporter, rate_limiter):
    DESCRIPTION: Creates a new file inclusion scanner.
    PROCESS:
        LOAD payloads from "webhunter/wordlists/file_inclusion/**/*.txt".
        INITIALIZE and return FileInclusionScanner instance.

FUNCTION FileInclusionScanner::payloads_count() -> usize:
    RETURNS the number of loaded payloads.

ASYNC FUNCTION FileInclusionScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for file inclusion vulnerabilities.
    PROCESS:
        CALL scan_urls(progress_bar)
        CALL scan_forms(progress_bar)
        RETURN Ok

ASYNC FUNCTION FileInclusionScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for file inclusion.
    PROCESS:
        FOR each url in target_urls:
            IF url has no query parameters, CONTINUE
            FOR i in 0..query_pairs.len():
                FOR each payload in payloads:
                    BUILD new_url with payload
                    AWAIT rate_limiter.wait()
                    SEND GET request
                    INCREMENT progress_bar
                    IF response status is not 404:
                        IF is_vulnerable(body, payload) returns Some(vuln_type):
                            CREATE Vulnerability
                            CALL reporter.report_file_inclusion()
                            CONTINUE to next parameter loop

ASYNC FUNCTION FileInclusionScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for file inclusion.
    PROCESS:
        FOR each form in forms:
            FOR i in 0..form.inputs.len():
                FOR each payload in payloads:
                    BUILD form_data with payload
                    AWAIT rate_limiter.wait()
                    SEND request (GET or POST)
                    INCREMENT progress_bar
                    IF response status is not 404:
                        IF is_vulnerable(body, payload) returns Some(vuln_type):
                            CREATE Vulnerability
                            CALL reporter.report_file_inclusion()
                            CONTINUE to next input loop

FUNCTION is_vulnerable(body, payload) -> Option<String>:
    DESCRIPTION: Checks for evidence of LFI or RFI in the response body.
    PROCESS:
        DEFINE lfi_evidence and rfi_evidence patterns.
        IF payload is a URL:
            CHECK for rfi_evidence in body, RETURN Some("RFI") if found.
        ELSE:
            CHECK for lfi_evidence in body, RETURN Some("LFI") if found.
        RETURN None
```

## File Inclusion Detection Logic

```pseudo
DETECTION_METHODS:
    - LFI (Local File Inclusion): Checks for content of local files (e.g., "root:x:0:0" from /etc/passwd).
    - RFI (Remote File Inclusion): Checks for content from remote URLs (e.g., "<title>Google</title>").

PAYLOAD_SOURCES:
    - Location: webhunter/wordlists/file_inclusion/*.txt
```