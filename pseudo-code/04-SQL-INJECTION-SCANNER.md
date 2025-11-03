# SQL Injection Scanner Module - Pseudo-Code
## File: sql_injection_scanner.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - tokio (async runtime)
    - indicatif (progress tracking)
    - std::time (timing measurements)

IMPORT modules:
    - form (Form structure)
    - rate_limiter (RateLimiter structure)
    - reporter (Reporter structure)

STRUCTURE SqlInjectionVulnerability:
    FIELDS:
        url: Url
        parameter: String
        payload: String
        vuln_type: String

STRUCTURE SqlInjectionScanner:
    FIELDS:
        target_urls: Vector<Url>
        forms: Vector<Form>
        error_based_payloads: Vector<String>
        boolean_based_payloads: Vector<(String, String)>
        time_based_payloads: Vector<String>
        reporter: &Arc<Reporter>
        rate_limiter: Arc<RateLimiter>

FUNCTION SqlInjectionScanner::new(target_urls, forms, reporter, rate_limiter):
    DESCRIPTION: Creates a new SQL injection scanner.
    PROCESS:
        LOAD error-based, boolean-based, and time-based payloads from wordlists.
        INITIALIZE and return SqlInjectionScanner instance.

FUNCTION SqlInjectionScanner::payloads_count() -> usize:
    RETURNS the total number of payloads.

ASYNC FUNCTION SqlInjectionScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for SQL injection.
    PROCESS:
        CALL scan_urls(progress_bar)
        CALL scan_forms(progress_bar)
        RETURN Ok

ASYNC FUNCTION SqlInjectionScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for all types of SQL injection.
    PROCESS:
        FOR each url in target_urls:
            IF url has no query parameters, CONTINUE
            FOR i in 0..query_pairs.len():
                IF test_error_based() finds vulnerability, CONTINUE to next parameter
                IF test_boolean_based() finds vulnerability, CONTINUE to next parameter
                IF test_time_based() finds vulnerability, BREAK

ASYNC FUNCTION SqlInjectionScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for all types of SQL injection.
    PROCESS:
        FOR each form in forms:
            FOR i in 0..form.inputs.len():
                IF test_form_error_based() finds vulnerability, CONTINUE to next input
                IF test_form_boolean_based() finds vulnerability, CONTINUE to next input
                IF test_form_time_based() finds vulnerability, BREAK

ASYNC FUNCTION test_error_based(client, url, payload, param_index, pb):
    DESCRIPTION: Tests for error-based SQLi in a URL parameter.
    PROCESS:
        BUILD new_url with payload
        AWAIT rate_limiter.wait()
        SEND GET request
        INCREMENT pb
        IF response body contains SQL error:
            CREATE Vulnerability
            CALL reporter.report_sql_injection()
            RETURN Ok(true)
        RETURN Ok(false)

ASYNC FUNCTION test_boolean_based(client, url, true_payload, false_payload, param_index, pb):
    DESCRIPTION: Tests for boolean-based SQLi in a URL parameter.
    PROCESS:
        BUILD true_url and false_url
        AWAIT rate_limiter.wait() twice
        SEND GET requests for both URLs
        INCREMENT pb by 2
        IF response bodies are different:
            CREATE Vulnerability
            CALL reporter.report_sql_injection()
            RETURN Ok(true)
        RETURN Ok(false)

ASYNC FUNCTION test_time_based(client, url, payload, param_index, pb):
    DESCRIPTION: Tests for time-based SQLi in a URL parameter.
    PROCESS:
        BUILD new_url with payload
        RECORD start time
        AWAIT rate_limiter.wait()
        SEND GET request
        CALCULATE duration
        INCREMENT pb
        IF duration > 2 seconds:
            CREATE Vulnerability
            CALL reporter.report_sql_injection()
            RETURN Ok(true)
        RETURN Ok(false)

ASYNC FUNCTION test_form_error_based(...):
    (Similar logic to test_error_based but for forms)

ASYNC FUNCTION test_form_boolean_based(...):
    (Similar logic to test_boolean_based but for forms)

ASYNC FUNCTION test_form_time_based(...):
    (Similar logic to test_time_based but for forms)

FUNCTION is_error_based_vulnerable(body) -> bool:
    DESCRIPTION: Checks for common SQL error messages in the response body.
    PROCESS:
        ITERATE through a list of known SQL error patterns.
        RETURN true if a pattern is found.
```

## SQL Injection Detection Methods

```pseudo
DETECTION_TECHNIQUES:
    1. Error-Based: Injects payloads to trigger database errors and looks for error messages in the response.
    2. Boolean-Based Blind: Sends two requests with different boolean conditions and compares the responses.
    3. Time-Based Blind: Injects a time-delay payload and measures the response time.

PAYLOAD_SOURCES:
    - Error-Based: wordlists/sql_injection/error_based.txt, wordlists/sql_injection/original_payloads.txt
    - Boolean-Based: wordlists/sql_injection/boolean_based.txt
    - Time-Based: wordlists/sql_injection/time_based.txt
```