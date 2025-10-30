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


STRUCTURE Vulnerability:
    DESCRIPTION: Represents a discovered XSS vulnerability
    
    FIELDS:
        url: URL                    // Vulnerable URL
        parameter: String           // Vulnerable parameter name
        payload: String             // Successful XSS payload
        vuln_type: String          // "Reflected" or "Stored"
        severity: String           // "Medium" or "High"


STRUCTURE XssScanner:
    DESCRIPTION: Scans for Cross-Site Scripting vulnerabilities
    
    FIELDS:
        target_urls: Vector<URL>    // URLs to test
        forms: Vector<Form>         // Forms to test
        payloads: Vector<String>    // XSS payloads


FUNCTION XssScanner::new(target_urls, forms):
    DESCRIPTION: Creates new XSS scanner with payloads from wordlists
    
    INPUT:
        target_urls: Vector of URLs to scan
        forms: Vector of Forms to scan
    
    OUTPUT:
        XssScanner instance
    
    PROCESS:
        INITIALIZE payloads as empty Vector
        
        // Load XSS payloads from wordlist directory
        TRY:
            READ directory "wordlists/xss"
            
            FOR EACH file IN directory:
                IF file extension is ".txt":
                    OPEN file for reading
                    
                    FOR EACH line IN file:
                        ADD line to payloads Vector
        CATCH error:
            // Continue with empty payloads
            PASS
        
        CREATE scanner with target_urls, forms, payloads
        RETURN scanner


FUNCTION XssScanner::payloads_count():
    DESCRIPTION: Returns the number of payloads loaded
    
    OUTPUT:
        Number of payloads
    
    RETURN length of payloads Vector


ASYNC FUNCTION XssScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for XSS vulnerabilities
    
    INPUT:
        progress_bar: ProgressBar reference
    
    OUTPUT:
        Result containing Vector<Vulnerability> or Error
    
    PROCESS:
        CALL scan_urls(progress_bar)
        STORE as url_vulnerabilities
        
        CALL scan_forms(progress_bar)
        STORE as form_vulnerabilities
        
        COMBINE url_vulnerabilities and form_vulnerabilities
        RETURN combined list


ASYNC FUNCTION XssScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for XSS vulnerabilities
    
    INPUT:
        progress_bar: ProgressBar reference
    
    OUTPUT:
        Result containing Vector<Vulnerability> or Error
    
    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        CREATE HTTP client
        
        FOR EACH url IN target_urls:
            // Skip URLs without parameters
            IF url has no query parameters:
                CONTINUE to next URL
            
            // Test each payload
            FOR EACH payload IN payloads:
                EXTRACT query_pairs from url
                
                // Test each parameter individually
                FOR i FROM 0 TO length(query_pairs) - 1:
                    INITIALIZE new_query_parts as empty Vector
                    INITIALIZE tested_param as empty String
                    
                    // Build modified query string
                    FOR j FROM 0 TO length(query_pairs) - 1:
                        IF i == j:
                            // Inject payload into this parameter
                            ADD "{key}={payload}" to new_query_parts
                            SET tested_param = key
                        ELSE:
                            // Keep original value
                            ADD "{key}={value}" to new_query_parts
                    
                    JOIN new_query_parts with "&"
                    CREATE new_url with modified query string
                    
                    // Send request
                    TRY:
                        SEND GET request to new_url
                        STORE response
                        
                        // Skip 404 responses
                        IF response.status == 404:
                            CONTINUE to next parameter
                        
                        GET response body as text
                        
                        // Check if payload is reflected
                        IF is_vulnerable(body, payload):
                            CREATE Vulnerability:
                                url = original url
                                parameter = tested_param
                                payload = payload
                                vuln_type = "Reflected"
                                severity = "Medium"
                            ADD vulnerability to vulnerabilities Vector
                    CATCH error:
                        // Skip on error
                        PASS
                    
                    // Rate limiting
                    SLEEP for 50 milliseconds
                    INCREMENT progress_bar by 1
        
        RETURN Ok(vulnerabilities)


ASYNC FUNCTION XssScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for reflected and stored XSS
    
    INPUT:
        progress_bar: ProgressBar reference
    
    OUTPUT:
        Result containing Vector<Vulnerability> or Error
    
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
                            // Inject payload into this input
                            SET form_data[input.name] = payload
                            SET tested_param = input.name
                        ELSE:
                            // Use original value
                            SET form_data[input.name] = input.value
                    
                    // Construct action URL
                    TRY:
                        RESOLVE form.action against form.url
                        STORE as action_url
                    CATCH error:
                        CONTINUE to next input
                    
                    // Preserve existing query parameters
                    EXTRACT original_query from action_url
                    
                    // Submit form
                    IF form.method is "POST":
                        // Merge query params into POST data
                        ADD original_query parameters to form_data
                        SEND POST request to action_url with form_data
                    ELSE:
                        // Preserve query params and add form data
                        APPEND original_query to action_url
                        SEND GET request to action_url with form_data as query
                    
                    STORE as response
                    
                    // Check for reflected XSS
                    IF response is successful:
                        IF response.status != 404:
                            GET response body as text
                            
                            IF is_vulnerable(body, payload):
                                CREATE Vulnerability:
                                    url = form.url
                                    parameter = tested_param
                                    payload = payload
                                    vuln_type = "Reflected"
                                    severity = "Medium"
                                ADD vulnerability to vulnerabilities Vector
                    
                    // Check for stored XSS
                    // Revisit the action URL to see if payload persists
                    SEND GET request to action_url
                    STORE as stored_response
                    
                    IF stored_response is successful:
                        IF stored_response.status != 404:
                            GET stored_response body as text
                            
                            IF is_vulnerable(body, payload):
                                CREATE Vulnerability:
                                    url = form.url
                                    parameter = tested_param
                                    payload = payload
                                    vuln_type = "Stored"
                                    severity = "High"
                                ADD vulnerability to vulnerabilities Vector
                    
                    // Rate limiting
                    SLEEP for 50 milliseconds
                    INCREMENT progress_bar by 1
        
        RETURN Ok(vulnerabilities)


FUNCTION XssScanner::is_vulnerable(body, payload):
    DESCRIPTION: Checks if XSS payload is present in response
    
    INPUT:
        body: HTTP response body as string
        payload: Injected XSS payload
    
    OUTPUT:
        Boolean indicating vulnerability
    
    ALGORITHM:
        // Check for direct payload reflection
        CREATE sanitized_payload by replacing ' with " in payload
        
        IF body contains sanitized_payload:
            RETURN true
        
        // Check if payload appears in HTML attributes
        PARSE body as HTML document
        
        FOR EACH element IN document:
            FOR EACH attribute IN element.attributes:
                IF attribute.value contains payload:
                    RETURN true
        
        RETURN false
```

## XSS Detection Logic

```pseudo
DETECTION_METHODS:
    
    1. Direct String Matching:
       - Search for exact payload in response body
       - Accounts for quote sanitization (' → ")
    
    2. Attribute Injection Detection:
       - Parse HTML to find payload in element attributes
       - Catches: <input value="PAYLOAD">
    
    3. Stored XSS Detection:
       - Submit payload via form
       - Revisit same page
       - Check if payload persists


VULNERABILITY_TYPES:
    
    Reflected XSS:
        - Payload appears in immediate response
        - Severity: Medium
        - Common in search queries, error messages
    
    Stored XSS:
        - Payload persists on server
        - Severity: High
        - Common in comments, user profiles


PAYLOAD_SOURCES:
    Location: wordlists/xss/*.txt
    Types:
        - Basic script tags: <script>alert(1)</script>
        - Event handlers: <img src=x onerror=alert(1)>
        - Encoded payloads: HTML entities, URL encoding
        - Polyglot payloads: Work in multiple contexts
```

## Testing Strategy

```pseudo
TESTING_APPROACH:
    
    For URLs:
        1. Identify URLs with query parameters
        2. For each parameter:
           a. Inject each payload
           b. Keep other parameters unchanged
           c. Send request
           d. Check response for payload
    
    For Forms:
        1. For each form input:
           a. Inject payload into that input
           b. Keep other inputs at default values
           c. Submit form
           d. Check response (reflected)
           e. Revisit page (stored)


OPTIMIZATION:
    - Parallel testing NOT used (avoids false positives)
    - Rate limiting: 50ms between requests
    - Skip 404 responses
    - Stop on first vulnerability per parameter (optional)


RATE_LIMITING:
    Purpose: Avoid overwhelming target server
    Delay: 50ms between each request
    Throughput: ~20 requests per second
```

## Edge Cases

```pseudo
EDGE_CASES:
    
    1. Quote Sanitization:
       - Server converts ' to "
       - Scanner checks both versions
    
    2. HTML Encoding:
       - Server encodes < > & characters
       - Scanner uses HTML parser to detect
    
    3. 404 Responses:
       - Skipped to avoid false positives
    
    4. Empty Forms:
       - Forms with no inputs are skipped
    
    5. Form Action Resolution:
       - Relative URLs resolved against form's page URL
    
    6. Mixed GET/POST Forms:
       - Handles both methods appropriately
    
    7. Query String Preservation:
       - Original query params maintained in form submission
```
