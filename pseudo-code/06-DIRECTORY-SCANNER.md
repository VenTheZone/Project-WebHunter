# Directory Scanner Module - Pseudo-Code
## File: dir_scanner.rs

```pseudo
IMPORT libraries:
    - reqwest (HTTP client)
    - url (URL manipulation)
    - serde (JSON deserialization)
    - std::process (external command execution)
    - indicatif (progress tracking)


STRUCTURE FeroxResponse:
    DESCRIPTION: Deserializes JSON output from feroxbuster

    FIELDS:
        url: String                 // Discovered URL
        status: u16                 // HTTP status code
        content_length: u64         // Response size in bytes


STRUCTURE DirScanner:
    DESCRIPTION: Scans for open directories using feroxbuster

    FIELDS:
        target_url: URL             // Target website
        wordlist_path: Optional<String>  // Custom wordlist path
        pb: ProgressBar reference   // Progress tracking


FUNCTION DirScanner::new(target_url, progress_bar, wordlist_path):
    DESCRIPTION: Creates a new directory scanner

    INPUT:
        target_url: Target URL to scan
        progress_bar: Progress bar reference
        wordlist_path: Optional custom wordlist

    OUTPUT:
        DirScanner instance

    PROCESS:
        CREATE scanner
        SET target_url = target_url
        SET wordlist_path = wordlist_path
        SET pb = progress_bar
        RETURN scanner


ASYNC FUNCTION DirScanner::scan():
    DESCRIPTION: Executes feroxbuster to find directories

    OUTPUT:
        Result containing Vector<(URL, status_code, content_length)> or Error

    ALGORITHM:
        // Determine wordlist to use
        IF wordlist_path is provided:
            SET wordlist = wordlist_path
        ELSE:
            SET wordlist = "default_wordlist.txt"

        // Build feroxbuster command arguments
        CREATE args = [
            "-u", target_url.as_string(),
            "--json",           // Output in JSON format
            "--silent",         // Suppress banner and runtime info
            "-w", wordlist      // Wordlist path
        ]

        // Update progress
        SET progress_bar message "Running feroxbuster..."

        // Execute feroxbuster
        TRY:
            SPAWN process "feroxbuster" with args
            SET stdout to pipe
            SET stderr to null (suppress errors)

            WAIT for process to complete
            STORE output
        CATCH command not found:
            RETURN Error "feroxbuster not found. Please install it."
        CATCH other error:
            RETURN Error with details

        // Process completed
        SET progress_bar message "Feroxbuster scan complete"

        // Parse JSON output
        INITIALIZE results as empty Vector
        CONVERT output to string

        FOR EACH line IN output:
            TRY:
                PARSE line as FeroxResponse JSON

                // Filter out 404 responses
                IF response.status != 404:
                    TRY:
                        PARSE response.url as URL
                        ADD (url, status, content_length) to results
                    CATCH URL parse error:
                        SKIP this line
            CATCH JSON parse error:
                SKIP this line

        RETURN Ok(results)
```

## Feroxbuster Integration

```pseudo
FEROXBUSTER_OVERVIEW:
    Name: feroxbuster
    Purpose: Fast directory and file brute-forcing tool
    Written in: Rust
    Speed: Very fast (concurrent requests)
    Output: JSON for easy parsing


COMMAND_STRUCTURE:
    feroxbuster -u <URL> -w <WORDLIST> --json --silent

    Flags:
        -u, --url <URL>
            Target URL

        -w, --wordlist <PATH>
            Wordlist file path

        --json
            Output results in JSON format

        --silent
            Suppress banner and progress info


JSON_OUTPUT_FORMAT:
    Each discovered resource is a JSON line:
    {
        "url": "http://example.com/admin",
        "status": 200,
        "content_length": 4567,
        "line_count": 123,
        "word_count": 456,
        "method": "GET"
    }


WORDLIST_SOURCES:
    Default: default_wordlist.txt

    Based on SecLists raft-large:
        - Common directory names
        - Admin panels
        - Configuration files
        - Backup files
        - Development files
        - API endpoints

    Custom: User can provide their own via --wordlist flag
```

## Algorithm Flow

```pseudo
SCANNING_FLOW:

    1. Initialization:
       - Validate target URL
       - Select wordlist (custom or default)
       - Initialize progress bar

    2. Execution:
       - Build feroxbuster command
       - Spawn subprocess
       - Capture stdout (JSON output)
       - Suppress stderr (errors)
       - Wait for completion

    3. Parsing:
       - Read JSON output line by line
       - Deserialize each line as FeroxResponse
       - Filter out 404 responses
       - Convert string URLs to URL objects
       - Collect (URL, status, size) tuples

    4. Return:
       - Return vector of discovered directories
       - Report findings to main application


ERROR_HANDLING:

    1. Feroxbuster Not Installed:
       - Check if command exists
       - Return descriptive error
       - Main app offers to install

    2. Invalid Wordlist:
       - feroxbuster will error
       - Caught and propagated

    3. Network Errors:
       - feroxbuster handles internally
       - May return empty results

    4. JSON Parse Errors:
       - Skip malformed lines
       - Continue processing valid lines

    5. URL Parse Errors:
       - Skip invalid URLs
       - Continue with next entry
```

## Wordlist Strategy

```pseudo
DEFAULT_WORDLIST_CONTENTS:
    Categories:
        - Admin interfaces:
            admin, administrator, admin-panel, wp-admin

        - Configuration files:
            config.php, .env, settings.ini

        - Backup files:
            backup, .git, .svn, .bak

        - Common directories:
            images, css, js, uploads, files

        - API endpoints:
            api, v1, v2, graphql, rest

        - Development:
            test, dev, staging, debug

        - Sensitive files:
            .htaccess, phpinfo.php, info.php


WORDLIST_OPTIMIZATION:
    Size: Large (thousands of entries)
    Source: SecLists raft-large collection
    Deduplication: Performed during build
    Sorting: By likelihood/commonality
```

## Security Considerations

```pseudo
POLITE_SCANNING:
    - feroxbuster uses concurrent requests
    - Can be aggressive by default
    - No custom rate limiting in WebHunter wrapper
    - Relies on feroxbuster's built-in limits


DETECTION_AVOIDANCE:
    - Single user-agent (feroxbuster default)
    - No randomization in this module
    - May trigger WAF/IDS if target is protected

    Recommendations:
        - Use on authorized targets only
        - Consider --rate-limit flag for production
        - Monitor target server load


FINDINGS_CLASSIFICATION:
    Status Codes:
        200 OK: Directory/file accessible
        301 Moved: Redirect (usually valid)
        302 Found: Temporary redirect
        403 Forbidden: Exists but access denied
        401 Unauthorized: Authentication required
        404 Not Found: Filtered out (doesn't exist)
        500 Internal Error: May indicate vulnerability
```

## Data Structures

```pseudo
INPUT:
    target_url: URL
        Example: "http://example.com"

    wordlist_path: Option<String>
        Example: Some("custom_wordlist.txt")
        Example: None (use default)

    progress_bar: &ProgressBar
        Reference to progress tracker


OUTPUT:
    Result<Vec<(URL, u16, u64)>, std::io::Error>

    Success: Vector of tuples
        (
            URL("http://example.com/admin"),
            200,  // status code
            4567  // content length in bytes
        )

    Error: IO error with description


INTERMEDIATE:
    FeroxResponse struct (JSON deserialization)
        url: String
        status: u16
        content_length: u64
```

## Process Management

```pseudo
SUBPROCESS_HANDLING:

    Spawn Process:
        Command::new("feroxbuster")
            .args(arguments)
            .stdout(Stdio::piped())    // Capture output
            .stderr(Stdio::null())      // Suppress errors
            .spawn()

    Wait for Completion:
        child.wait_with_output()
        - Blocks until feroxbuster finishes
        - Returns stdout, stderr, exit status

    Exit Status:
        IF output.status.success():
            Process completed successfully
        ELSE:
            Process failed (handled by feroxbuster)
```

## Example Usage Flow

```pseudo
EXAMPLE_EXECUTION:

    User Input:
        Target: http://testphp.vulnweb.com
        Scanner: Open Directory
        Wordlist: default

    Execution:
        1. Create DirScanner with target URL
        2. Call scan()
        3. feroxbuster runs with arguments:
           feroxbuster -u http://testphp.vulnweb.com
                       -w default_wordlist.txt
                       --json --silent
        4. feroxbuster discovers:
           - /admin (403)
           - /images (200)
           - /backup (200)
           - /config.php (200)
        5. Parse JSON output
        6. Return results to main
        7. Main generates report

    Report:
        testphp_vulnweb_com/Open-Directories-output.md
        - Lists all discovered directories
        - Shows status codes and sizes
        - Provides remediation advice
```

## Comparison with Other Tools

```pseudo
WHY_FEROXBUSTER:

    Advantages:
        - Written in Rust (fast, memory-safe)
        - Concurrent requests (high speed)
        - JSON output (easy parsing)
        - Well-maintained open source
        - Comprehensive discovery

    Alternatives:
        - dirb (slower, C-based)
        - gobuster (Go, fast but less features)
        - dirbuster (Java, GUI-based)
        - wfuzz (Python, flexible but slower)

    Integration Benefits:
        - Both WebHunter and feroxbuster in Rust
        - Shared ecosystem
        - Easy installation via cargo
        - Consistent toolchain
```
