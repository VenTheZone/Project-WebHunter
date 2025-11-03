# Directory Scanner Module - Pseudo-Code
## File: dir_scanner.rs

```pseudo
IMPORT libraries:
    - serde (JSON deserialization)
    - std::process (external command execution)
    - indicatif (progress tracking)

IMPORT modules:
    - reporter (Reporter structure)

STRUCTURE FeroxResponse:
    DESCRIPTION: Deserializes JSON output from feroxbuster.
    FIELDS:
        url: String
        status: u16
        content_length: u64

STRUCTURE DirScanner:
    FIELDS:
        target_url: Url
        wordlist_path: Option<String>
        pb: &ProgressBar
        reporter: &Arc<Reporter>

FUNCTION DirScanner::new(target_url, pb, wordlist_path, reporter):
    DESCRIPTION: Creates a new directory scanner.
    PROCESS:
        INITIALIZE and return DirScanner instance.

ASYNC FUNCTION DirScanner::scan():
    DESCRIPTION: Executes feroxbuster to find directories.
    PROCESS:
        DETERMINE wordlist to use (default or custom).
        BUILD feroxbuster command arguments (--json, --silent, etc.).
        SET progress bar message "Running feroxbuster...".
        SPAWN feroxbuster process with stdout piped.
        IF stdout is available:
            READ output line by line.
            DESERIALIZE each line into a FeroxResponse.
            IF status is not 404:
                PRINT confirmation message.
                CALL reporter.report_directory().
        AWAIT child process to finish.
        FINISH progress bar.
        RETURN Ok.
```

## Feroxbuster Integration

```pseudo
COMMAND_STRUCTURE:
    feroxbuster -u <URL> -w <WORDLIST> --json --silent

JSON_OUTPUT_FORMAT:
    - Each discovered resource is a JSON object on a new line.
    - Example: {"url": "http://example.com/admin", "status": 200, ...}

WORDLIST_SOURCES:
    - Default: webhunter/default_wordlist.txt
    - Custom: Provided via the --wordlist flag.
```

## Algorithm Flow

```pseudo
SCANNING_FLOW:
    1. Initialization: Get target URL and wordlist.
    2. Execution: Spawn feroxbuster as a subprocess.
    3. Parsing: Read and parse the JSON output in real-time.
    4. Reporting: Report findings as they are discovered.
    5. Completion: Wait for the process to end.

ERROR_HANDLING:
    - Errors from spawning the process are propagated.
    - JSON and URL parsing errors are handled gracefully, skipping the invalid lines.
```