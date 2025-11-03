# 403/401 Bypass Scanner - Pseudo-Code
## File: bypass_403.rs

```pseudo
IMPORT modules:
    - rate_limiter (RateLimiter structure)
    - snapshot (for taking snapshots)
    - reporter (Reporter structure)

STRUCTURE BypassBypass:
    FIELDS:
        url: Url
        bypass_url: Url
        method: String
        technique: String
        severity: String
        headers: String

STRUCTURE BypassScanner:
    FIELDS:
        target_url: Url
        directories: Vector<String>
        header_payloads: Vector<(String, String)>
        url_payloads: Vector<String>
        methods: Vector<String>
        user_agents: Vector<String>
        pb: &ProgressBar
        reporter: &Arc<Reporter>
        rate_limiter: Arc<RateLimiter>

FUNCTION BypassScanner::new(target_url, pb, reporter, rate_limiter):
    DESCRIPTION: Creates a new BypassScanner instance.
    PROCESS:
        LOAD directories, header_payloads, url_payloads, methods, and user_agents from wordlists.
        INITIALIZE and return BypassScanner instance.

ASYNC FUNCTION BypassScanner::scan():
    DESCRIPTION: Scans for 403/401 bypasses.
    PROCESS:
        FOR each directory in directories:
            BUILD test_url.
            AWAIT rate_limiter.wait().
            SEND GET request to test_url.
            IF status is 403:
                IF try_bypass_directory() finds a bypass:
                    CALL reporter.report_403_bypass().

ASYNC FUNCTION try_bypass_directory(client, original_url, directory, original_body) -> Option<BypassBypass>:
    DESCRIPTION: Tries various techniques to bypass a 403 forbidden directory.
    PROCESS:
        GENERATE bypass techniques (URL manipulations).
        FOR each technique:
            // Test with GET, other methods, and header spoofing
            IF check_bypass() with GET finds a bypass:
                PRINT details, TAKE snapshot, and RETURN bypass.
            FOR each method in methods:
                IF check_bypass() with the method finds a bypass:
                    PRINT details, TAKE snapshot, and RETURN bypass.
            FOR each header payload and user agent:
                IF check_bypass() with header spoofing finds a bypass:
                    PRINT details, TAKE snapshot, and RETURN bypass.
        RETURN None.

FUNCTION generate_bypass_techniques(original_url, directory) -> Vec<(Url, String)>:
    DESCRIPTION: Generates a vector of potential bypass URLs and technique names.

ASYNC FUNCTION check_bypass(args) -> Option<(BypassBypass, u16, String)>:
    DESCRIPTION: Checks if a specific bypass technique is successful.
    PROCESS:
        BUILD request with specified method and headers.
        SEND request.
        IF status is 200 and response body is different from original:
            CREATE and RETURN BypassBypass struct, status, and body.
        RETURN None.

FUNCTION print_fancy_bypass(bypass, status):
    DESCRIPTION: Prints a formatted, colored output to the console for a successful bypass.
```

## Bypass Techniques

```pseudo
URL-BASED TECHNIQUES:
    - Appending various suffixes and prefixes from `url_payloads.txt` to the directory.

METHOD-BASED TECHNIQUES:
    - Trying different HTTP methods like POST, PUT, PATCH, etc., from `methods.txt`.

HEADER-SPOOFING TECHNIQUES:
    - Using a combination of header payloads from `http_headers.txt` and user agents from `user_agents.txt`.
```