# Reporter Module - Pseudo-Code
## File: reporter.rs

```pseudo
IMPORT libraries:
    - std::fs (file system operations)
    - std::io (I/O operations)
    - url (URL manipulation)
    - chrono (date/time handling)

IMPORT modules:
    - xss (Vulnerability structure)
    - sql_injection_scanner (SqlInjectionVulnerability)
    - file_inclusion_scanner (FileInclusionVulnerability)


STRUCTURE Reporter:
    DESCRIPTION: Generates vulnerability reports in various formats


FUNCTION Reporter::new():
    DESCRIPTION: Creates a new reporter instance

    OUTPUT:
        Reporter instance

    PROCESS:
        CREATE and RETURN new Reporter


FUNCTION Reporter::report(vulnerabilities, target_url):
    DESCRIPTION: Generates XSS vulnerability report in Markdown

    INPUT:
        vulnerabilities: Slice of Vulnerability structs
        target_url: Target URL reference

    OUTPUT:
        Result indicating success or IO error

    ALGORITHM:
        // Create output directory
        EXTRACT domain from target_url OR use "unknown_domain"
        REPLACE "." with "_" in domain
        CREATE directory with domain name

        // Create report file
        SET file_path = "{domain}/XSS-output.md"
        CREATE file at file_path

        // Write report header
        WRITE "# WebHunter XSS Scan Report for {target_url}"
        WRITE "**Scan completed on:** {current_timestamp}"
        WRITE "---"

        // Write findings
        IF vulnerabilities is empty:
            WRITE "## No XSS vulnerabilities found."
        ELSE:
            FOR EACH vuln IN vulnerabilities:
                WRITE "## Vulnerability Found:"
                WRITE "- **URL:** {vuln.url}"
                WRITE "- **Type:** {vuln.vuln_type}"
                WRITE "- **Severity:** {vuln.severity}"
                WRITE "- **Parameter:** {vuln.parameter}"
                WRITE "- **Payload:** `{vuln.payload}`"
                WRITE "---"

        RETURN Ok(())


FUNCTION Reporter::report_sql_injection(vulnerabilities, target_url):
    DESCRIPTION: Generates SQL injection report in Markdown

    INPUT:
        vulnerabilities: Slice of SqlInjectionVulnerability structs
        target_url: Target URL reference

    OUTPUT:
        Result indicating success or IO error

    ALGORITHM:
        // Create output directory
        EXTRACT domain from target_url OR use "unknown_domain"
        REPLACE "." with "_" in domain
        CREATE directory with domain name

        // Create report file
        SET file_path = "{domain}/Sql-Injection-output.md"
        CREATE file at file_path

        // Write header
        WRITE "# WebHunter SQL Injection Scan Report for {target_url}"
        WRITE "**Scan completed on:** {current_timestamp}"
        WRITE "---"

        IF vulnerabilities is empty:
            WRITE "## No SQL injection vulnerabilities found."
        ELSE:
            // Write summary section
            WRITE "## Summary"
            WRITE "WebHunter discovered one or more SQL injection vulnerabilities."
            WRITE "This could allow an attacker to execute arbitrary SQL queries,"
            WRITE "bypass authentication, or exfiltrate sensitive data from the database."
            WRITE ""

            // Write description section
            WRITE "## Description"
            WRITE "SQL Injection is a web security vulnerability that allows an attacker"
            WRITE "to interfere with the queries that an application makes to its database."
            WRITE "It generally allows an attacker to view data that they are not"
            WRITE "normally able to retrieve."
            WRITE ""

            // Write impact section
            WRITE "## Impact"
            WRITE "Successful exploitation of an SQL Injection vulnerability can result in"
            WRITE "unauthorized access to sensitive data, such as passwords, credit card"
            WRITE "details, or personal user information. It can also be used to modify"
            WRITE "or delete this data, causing persistent changes to the application's"
            WRITE "content or behavior."
            WRITE ""

            // Write remediation section
            WRITE "## Remediation"
            WRITE "The most effective way to prevent SQL injection is to use parameterized"
            WRITE "queries (also known as prepared statements). This practice ensures that"
            WRITE "user-supplied input is treated as data and not as part of the SQL command."
            WRITE "---"

            // Write findings table
            WRITE "## Findings"
            WRITE "| URL | Parameter | Type | Payload | Severity |"
            WRITE "|---|---|---|---|---|"

            FOR EACH vuln IN vulnerabilities:
                WRITE "| [{vuln.url}]({vuln.url}) | {vuln.parameter} | {vuln.vuln_type} | `{vuln.payload}` | High |"

        RETURN Ok(())


FUNCTION Reporter::report_file_inclusion(vulnerabilities, target_url):
    DESCRIPTION: Generates file inclusion report in plain text

    INPUT:
        vulnerabilities: Slice of FileInclusionVulnerability structs
        target_url: Target URL reference

    OUTPUT:
        Result indicating success or IO error

    ALGORITHM:
        // Create output directory
        EXTRACT domain from target_url OR use "unknown_domain"
        REPLACE "." with "_" in domain
        CREATE directory with domain name

        // Create report file
        SET file_path = "{domain}/File-Inclusion-output.txt"
        CREATE file at file_path

        // Write header
        WRITE "WebHunter File Inclusion Scan Report for {target_url}"
        WRITE "Scan completed on: {current_timestamp}"
        WRITE "--------------------------------------------------"

        // Write findings
        IF vulnerabilities is empty:
            WRITE "No file inclusion vulnerabilities found."
        ELSE:
            FOR EACH vuln IN vulnerabilities:
                WRITE "Vulnerability Found:"
                WRITE "  URL: {vuln.url}"
                WRITE "  Type: {vuln.vuln_type}"
                WRITE "  Parameter: {vuln.parameter}"
                WRITE "  Payload: {vuln.payload}"
                WRITE "--------------------------------------------------"

        RETURN Ok(())


FUNCTION Reporter::report_dirs(found_dirs, target_url, wordlist):
    DESCRIPTION: Generates open directory report in Markdown

    INPUT:
        found_dirs: Slice of (URL, status_code, content_length) tuples
        target_url: Target URL reference
        wordlist: Wordlist file name used

    OUTPUT:
        Result indicating success or IO error

    ALGORITHM:
        // Create output directory
        EXTRACT domain from target_url OR use "unknown_domain"
        REPLACE "." with "_" in domain
        CREATE directory with domain name

        // Create report file
        SET file_path = "{domain}/Open-Directories-output.md"
        CREATE file at file_path

        // Write header
        WRITE "# WebHunter Open Directory Scan Report for {target_url}"
        WRITE "**Scan completed on:** {current_timestamp}"
        WRITE "---"

        IF found_dirs is empty:
            WRITE "## No open directories found."
        ELSE:
            // Write summary
            WRITE "## Summary"
            WRITE "WebHunter discovered one or more open directories on the target server."
            WRITE "This could lead to the exposure of sensitive information."
            WRITE ""

            // Write scan details
            WRITE "## Scan Details"
            WRITE "- **Tool Used:** feroxbuster"
            WRITE "- **Command:** `feroxbuster -u {target_url} -w {wordlist} --json --silent`"
            WRITE ""

            // Write description
            WRITE "## Description"
            WRITE "Open directories, also known as directory listing, is a feature that,"
            WRITE "when enabled, lists the contents of a directory when no index file is present."
            WRITE "This can expose sensitive information to attackers, such as configuration files,"
            WRITE "source code, or other confidential data."
            WRITE ""

            // Write impact
            WRITE "## Impact"
            WRITE "Exposure of sensitive data and information leakage that could aid further attacks."
            WRITE ""

            // Write steps to reproduce
            WRITE "## Steps to Reproduce"
            WRITE "The following URLs can be accessed with a web browser to view the directory contents:"
            WRITE ""

            // Write remediation
            WRITE "## Remediation"
            WRITE "Disable directory listing on your web server. For example, on an Apache server,"
            WRITE "you can add `Options -Indexes` to your `.htaccess` file or server configuration."
            WRITE "---"

            // Write findings table
            WRITE "## Findings"
            WRITE "| URL | Status | Content-Length | Severity |"
            WRITE "|---|---|---|---|"

            FOR EACH (url, status, content_length) IN found_dirs:
                WRITE "| [{url}]({url}) | {status} | {content_length} bytes | Medium |"

        RETURN Ok(())
```

## Report Formats

```pseudo
MARKDOWN_FORMAT:
    Files:
        - XSS-output.md
        - Sql-Injection-output.md
        - Open-Directories-output.md

    Structure:
        # Title
        **Metadata**
        ---
        ## Sections
        ### Findings

    Features:
        - Clickable URLs
        - Tables for structured data
        - Code blocks for payloads
        - Clear sections

    Advantages:
        - Human-readable
        - Can be converted to HTML/PDF
        - GitHub-friendly
        - Version control compatible


TEXT_FORMAT:
    Files:
        - File-Inclusion-output.txt

    Structure:
        Title
        Metadata
        ---
        Findings with indentation

    Features:
        - Plain text
        - Simple formatting
        - Universal compatibility

    Advantages:
        - Works everywhere
        - Scriptable
        - Lightweight


REPORT_SECTIONS:

    Header:
        - Tool name (WebHunter)
        - Target URL
        - Timestamp of scan

    Summary (for vulnerabilities):
        - Brief description
        - Potential impact
        - Attack explanation

    Technical Details:
        - Scan methodology
        - Tools used
        - Commands executed

    Findings:
        - Detailed list of vulnerabilities
        - Parameters/locations
        - Payloads used
        - Severity ratings

    Remediation:
        - How to fix vulnerabilities
        - Best practices
        - Code examples
```

## Directory Structure

```pseudo
OUTPUT_ORGANIZATION:

    Directory Naming:
        Pattern: {domain_with_underscores}
        Example: testphp_vulnweb_com

    File Naming:
        XSS: XSS-output.md
        SQL: Sql-Injection-output.md
        File Inclusion: File-Inclusion-output.txt
        Directory: Open-Directories-output.md

    Full Example:
        testphp_vulnweb_com/
        ├── XSS-output.md
        ├── Sql-Injection-output.md
        ├── File-Inclusion-output.txt
        └── Open-Directories-output.md


DIRECTORY_CREATION:
    Method: fs::create_dir_all()
    Behavior: Creates parent directories if needed
    Permissions: Default for current user
    Error Handling: Returns IO error if fails
```

## Severity Classification

```pseudo
SEVERITY_LEVELS:

    XSS:
        Reflected: Medium
            - Requires user interaction
            - Temporary impact

        Stored: High
            - Persistent threat
            - Affects all users

    SQL Injection: High
        - All types considered high
        - Can compromise entire database
        - Authentication bypass
        - Data exfiltration

    File Inclusion:
        LFI: High
            - Read sensitive files
            - Source code disclosure

        RFI: Critical
            - Remote code execution
            - Full system compromise

    Open Directories: Medium
        - Information disclosure
        - Aids reconnaissance
        - Potential sensitive data


CVSS_ALIGNMENT:
    Though not formally CVSS scored, severity aligns with:
        Critical: 9.0-10.0
        High: 7.0-8.9
        Medium: 4.0-6.9
        Low: 0.1-3.9
```

## Timestamp Formatting

```pseudo
TIMESTAMP_GENERATION:
    Library: chrono
    Function: Local::now()

    Format:
        2025-10-31 20:45:00 -05:00
        (Local time with timezone offset)

    Usage:
        Provides audit trail
        Helps with report versioning
        Legal compliance for security testing
```

## Error Handling

```pseudo
ERROR_CASES:

    1. Directory Creation Fails:
       - Permissions issue
       - Disk full
       - Invalid path

       Action: Return IO error

    2. File Creation Fails:
       - File already exists (overwritten)
       - Permissions issue

       Action: Return IO error

    3. Write Operations Fail:
       - Disk full
       - File system error

       Action: Return IO error

    4. Domain Extraction Fails:
       - Use "unknown_domain" as fallback
       - Continue with report generation


IDEMPOTENCY:
    Behavior: Reports can be regenerated
    File Handling: Overwrites existing reports
    Safety: Previous data lost on re-scan
```

## Usage Example

```pseudo
EXAMPLE_USAGE:

    // In main.rs after scanning
    CREATE reporter = Reporter::new()

    CALL reporter.report(&vulnerabilities, &target_url)
    IF error:
        PRINT "Error writing report: {error}"
    ELSE:
        PRINT "Report saved to {domain}/XSS-output.md"


TYPICAL_REPORT_SIZE:
    XSS Report:
        No vulns: ~500 bytes
        10 vulns: ~2-3 KB

    SQL Injection Report:
        Includes full documentation: ~3-4 KB base
        Per vuln: ~100 bytes additional

    Directory Report:
        100 directories: ~5-6 KB
```

## Future Enhancements (Potential)

```pseudo
POSSIBLE_IMPROVEMENTS:

    1. Multiple Format Support:
       - JSON output
       - XML output
       - CSV output
       - HTML with CSS

    2. Report Customization:
       - Templates
       - Company branding
       - Custom sections

    3. Report Aggregation:
       - Combine multiple scans
       - Trend analysis
       - Comparison reports

    4. Integration:
       - JIRA tickets
       - Email sending
       - Slack notifications

    5. Enhanced Metadata:
       - Scanner version
       - System information
       - Scan duration
       - Request count
```
