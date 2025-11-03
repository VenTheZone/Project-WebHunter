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


STRUCTURE SqlInjectionVulnerability:
    DESCRIPTION: Represents a discovered SQL injection vulnerability

    FIELDS:
        url: URL                    // Vulnerable URL
        parameter: String           // Vulnerable parameter name
        payload: String             // Successful SQL injection payload
        vuln_type: String          // "Error-Based", "Boolean-Based", or "Time-Based"


STRUCTURE SqlInjectionScanner:
    DESCRIPTION: Scans for SQL injection vulnerabilities

    FIELDS:
        target_urls: Vector<URL>                  // URLs to test
        forms: Vector<Form>                       // Forms to test
        error_based_payloads: Vector<String>      // Error-triggering payloads
        boolean_based_payloads: Vector<(String, String)>  // (true_payload, false_payload) pairs
        time_based_payloads: Vector<String>       // Time-delay payloads


FUNCTION SqlInjectionScanner::new(target_urls, forms):
    DESCRIPTION: Creates new SQL injection scanner with payloads

    INPUT:
        target_urls: Vector of URLs to scan
        forms: Vector of Forms to scan

    OUTPUT:
        SqlInjectionScanner instance

    PROCESS:
        // Load error-based payloads
        LOAD payloads from "wordlists/sql_injection/error_based.txt"
        EXTEND with "wordlists/sql_injection/original_payloads.txt"
        STORE as error_based_payloads

        // Load boolean-based payloads
        LOAD payload pairs from "wordlists/sql_injection/boolean_based.txt"
        PARSE each line as "true_payload/false_payload"
        STORE as boolean_based_payloads

        // Load time-based payloads
        LOAD payloads from "wordlists/sql_injection/time_based.txt"
        STORE as time_based_payloads

        CREATE scanner with all payloads
        RETURN scanner


FUNCTION SqlInjectionScanner::load_payloads(path):
    DESCRIPTION: Helper to load payloads from file

    INPUT:
        path: File path string

    OUTPUT:
        Vector of payload strings

    PROCESS:
        INITIALIZE payloads as empty Vector

        TRY:
            OPEN file at path
            READ line by line
            ADD each line to payloads
        CATCH error:
            // Return empty vector
            PASS

        RETURN payloads


FUNCTION SqlInjectionScanner::load_boolean_payloads(path):
    DESCRIPTION: Loads boolean payload pairs separated by "/"

    INPUT:
        path: File path string

    OUTPUT:
        Vector of (String, String) tuples

    PROCESS:
        INITIALIZE payloads as empty Vector

        TRY:
            OPEN file at path
            READ line by line

            FOR EACH line:
                SPLIT line by "/"
                IF split has 2 parts:
                    ADD (part[0], part[1]) to payloads
        CATCH error:
            // Return empty vector
            PASS

        RETURN payloads


FUNCTION SqlInjectionScanner::payloads_count():
    DESCRIPTION: Calculates total number of tests to perform

    OUTPUT:
        Total test count

    CALCULATION:
        error_tests = count of error_based_payloads
        boolean_tests = (count of boolean_based_payloads) * 2  // Two requests per test
        time_tests = count of time_based_payloads

        RETURN error_tests + boolean_tests + time_tests


ASYNC FUNCTION SqlInjectionScanner::scan(progress_bar):
    DESCRIPTION: Scans all URLs and forms for SQL injection

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<SqlInjectionVulnerability> or Error

    PROCESS:
        CALL scan_urls(progress_bar)
        STORE as url_vulnerabilities

        CALL scan_forms(progress_bar)
        STORE as form_vulnerabilities

        COMBINE url_vulnerabilities and form_vulnerabilities
        RETURN combined list


ASYNC FUNCTION SqlInjectionScanner::scan_urls(progress_bar):
    DESCRIPTION: Tests URL parameters for SQL injection

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<SqlInjectionVulnerability> or Error

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        CREATE HTTP client

        FOR EACH url IN target_urls:
            // Skip URLs without parameters
            IF url has no query parameters:
                CONTINUE to next URL

            // Test error-based injection
            FOR EACH payload IN error_based_payloads:
                EXTEND vulnerabilities with test_error_based(client, url, payload, progress_bar)

            // Test boolean-based injection
            FOR EACH (true_payload, false_payload) IN boolean_based_payloads:
                EXTEND vulnerabilities with test_boolean_based(client, url, true_payload, false_payload, progress_bar)

            // Test time-based injection
            FOR EACH payload IN time_based_payloads:
                EXTEND vulnerabilities with test_time_based(client, url, payload, progress_bar)

        RETURN Ok(vulnerabilities)


ASYNC FUNCTION SqlInjectionScanner::test_error_based(client, url, payload, progress_bar):
    DESCRIPTION: Tests for error-based SQL injection

    INPUT:
        client: HTTP client reference
        url: Target URL
        payload: SQL error-triggering payload
        progress_bar: ProgressBar reference

    OUTPUT:
        Vector of vulnerabilities found

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        EXTRACT query_pairs from url

        // Test each parameter
        FOR i FROM 0 TO length(query_pairs) - 1:
            INITIALIZE new_query_parts as empty Vector
            INITIALIZE tested_param as empty String

            // Inject payload into current parameter
            FOR j FROM 0 TO length(query_pairs) - 1:
                IF i == j:
                    ADD "{key}={value}{payload}" to new_query_parts
                    SET tested_param = key
                ELSE:
                    ADD "{key}={value}" to new_query_parts

            JOIN new_query_parts with "&"
            CREATE new_url with modified query

            // Send request
            TRY:
                SEND GET request to new_url
                IF response is successful:
                    GET response body

                    IF is_error_based_vulnerable(body):
                        CREATE SqlInjectionVulnerability:
                            url = original url
                            parameter = tested_param
                            payload = payload
                            vuln_type = "Error-Based"
                        ADD to vulnerabilities
            CATCH:
                PASS

            INCREMENT progress_bar by 1
            SLEEP for 50 milliseconds

        RETURN vulnerabilities


ASYNC FUNCTION SqlInjectionScanner::test_boolean_based(client, url, true_payload, false_payload, progress_bar):
    DESCRIPTION: Tests for boolean-based blind SQL injection

    INPUT:
        client: HTTP client reference
        url: Target URL
        true_payload: Payload that should return true
        false_payload: Payload that should return false
        progress_bar: ProgressBar reference

    OUTPUT:
        Vector of vulnerabilities found

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        EXTRACT query_pairs from url

        // Test each parameter
        FOR i FROM 0 TO length(query_pairs) - 1:
            INITIALIZE true_query_parts as empty Vector
            INITIALIZE false_query_parts as empty Vector
            INITIALIZE tested_param as empty String

            // Build two queries: one with true, one with false
            FOR j FROM 0 TO length(query_pairs) - 1:
                IF i == j:
                    ADD "{key}={value}{true_payload}" to true_query_parts
                    ADD "{key}={value}{false_payload}" to false_query_parts
                    SET tested_param = key
                ELSE:
                    ADD "{key}={value}" to both query_parts

            JOIN query parts
            CREATE true_url and false_url

            // Send both requests
            SEND GET request to true_url
            STORE as true_response

            SEND GET request to false_url
            STORE as false_response

            // Compare responses
            IF both responses successful:
                GET true_body and false_body

                // If responses differ, likely vulnerable
                IF true_body != false_body:
                    CREATE SqlInjectionVulnerability:
                        url = original url
                        parameter = tested_param
                        payload = "{true_payload} / {false_payload}"
                        vuln_type = "Boolean-Based"
                    ADD to vulnerabilities

            INCREMENT progress_bar by 2  // Two requests made
            SLEEP for 100 milliseconds

        RETURN vulnerabilities


ASYNC FUNCTION SqlInjectionScanner::test_time_based(client, url, payload, progress_bar):
    DESCRIPTION: Tests for time-based blind SQL injection

    INPUT:
        client: HTTP client reference
        url: Target URL
        payload: Time-delay SQL payload
        progress_bar: ProgressBar reference

    OUTPUT:
        Vector of vulnerabilities found

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        EXTRACT query_pairs from url

        // Test each parameter
        FOR i FROM 0 TO length(query_pairs) - 1:
            INITIALIZE new_query_parts as empty Vector
            INITIALIZE tested_param as empty String

            // Inject time-delay payload
            FOR j FROM 0 TO length(query_pairs) - 1:
                IF i == j:
                    ADD "{key}={value}{payload}" to new_query_parts
                    SET tested_param = key
                ELSE:
                    ADD "{key}={value}" to new_query_parts

            JOIN new_query_parts
            CREATE new_url

            // Measure response time
            RECORD start_time
            SEND GET request to new_url
            RECORD end_time
            CALCULATE duration = end_time - start_time

            // If response took longer than expected, likely vulnerable
            IF duration > 2 seconds:
                CREATE SqlInjectionVulnerability:
                    url = original url
                    parameter = tested_param
                    payload = payload
                    vuln_type = "Time-Based"
                ADD to vulnerabilities

            INCREMENT progress_bar by 1
            SLEEP for 50 milliseconds

        RETURN vulnerabilities


ASYNC FUNCTION SqlInjectionScanner::scan_forms(progress_bar):
    DESCRIPTION: Tests form inputs for SQL injection

    INPUT:
        progress_bar: ProgressBar reference

    OUTPUT:
        Result containing Vector<SqlInjectionVulnerability> or Error

    ALGORITHM:
        INITIALIZE vulnerabilities as empty Vector
        CREATE HTTP client

        FOR EACH form IN forms:
            // Test all three types of SQL injection
            FOR EACH payload IN error_based_payloads:
                EXTEND vulnerabilities with test_form_error_based(client, form, payload, progress_bar)

            FOR EACH (true_payload, false_payload) IN boolean_based_payloads:
                EXTEND vulnerabilities with test_form_boolean_based(client, form, true_payload, false_payload, progress_bar)

            FOR EACH payload IN time_based_payloads:
                EXTEND vulnerabilities with test_form_time_based(client, form, payload, progress_bar)

        RETURN Ok(vulnerabilities)


FUNCTION SqlInjectionScanner::is_error_based_vulnerable(body):
    DESCRIPTION: Checks if response contains SQL error messages

    INPUT:
        body: HTTP response body

    OUTPUT:
        Boolean indicating vulnerability

    ALGORITHM:
        DEFINE error_patterns = [
            // MySQL errors
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",

            // MSSQL errors
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",

            // Oracle errors
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",

            // PostgreSQL errors
            "ERROR: unterminated quoted string at or near",
            "ERROR: syntax error at or near",

            // SQLite errors
            "SQLite/JDBCDriver",
            "SQLITE_ERROR"
        ]

        FOR EACH pattern IN error_patterns:
            IF body contains pattern:
                RETURN true

        RETURN false
```

## SQL Injection Detection Methods

```pseudo
THREE_DETECTION_TECHNIQUES:

    1. Error-Based Detection:
       Method: Inject syntax-breaking payloads
       Detection: Look for database error messages in response
       Advantages: Clear and definitive
       Example: ' OR 1=1-- causes "SQL syntax error"

    2. Boolean-Based Blind Detection:
       Method: Inject true/false conditions
       Detection: Compare response differences
       Advantages: Works when errors are hidden
       Example:
           - id=1' AND 1=1-- returns normal page
           - id=1' AND 1=2-- returns different page

    3. Time-Based Blind Detection:
       Method: Inject time-delay functions
       Detection: Measure response time
       Advantages: Works when no visible difference
       Example: id=1'; WAITFOR DELAY '00:00:05'--
       Expected: Response takes 5+ seconds


PAYLOAD_EXAMPLES:

    Error-Based:
        - ' OR '1'='1
        - " OR "1"="1
        - ') OR ('1'='1
        - ' OR 1=1--
        - " OR 1=1--
        - '; DROP TABLE users--

    Boolean-Based (pairs):
        - ' AND '1'='1 / ' AND '1'='2
        - " AND "1"="1 / " AND "1"="2
        - 1' AND '1'='1 / 1' AND '1'='2

    Time-Based:
        - '; WAITFOR DELAY '00:00:05'--  (MSSQL)
        - '; SELECT SLEEP(5)--  (MySQL)
        - '; pg_sleep(5)--  (PostgreSQL)
        - ' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

## Algorithm Complexity

```pseudo
COMPLEXITY_ANALYSIS:

    Per URL/Form:
        E = error-based payloads
        B = boolean-based payload pairs
        T = time-based payloads
        P = parameters per URL/form

        Total Tests = P * (E + 2B + T)

        Example:
            3 parameters
            10 error payloads
            5 boolean pairs
            5 time payloads

            Total = 3 * (10 + 2*5 + 5) = 3 * 25 = 75 tests

    Time Complexity: O(URLs * Parameters * Payloads)

    Request Rate: ~10-20 requests/second (with delays)
```

## Edge Cases

```pseudo
EDGE_CASES:

    1. 404 Responses:
       - Skipped to avoid false positives

    2. Time-Based False Positives:
       - Threshold set to 2 seconds (for 5-second delays)
       - Network latency considered

    3. Boolean-Based False Positives:
       - Only flag if responses significantly differ
       - Exact string comparison used

    4. Error Message Variations:
       - 12 different error patterns checked
       - Covers MySQL, MSSQL, Oracle, PostgreSQL, SQLite

    5. Parameter Position:
       - Each parameter tested individually
       - Others keep original values

    6. Form Method Handling:
       - POST: Data in body
       - GET: Data in query string
```
