# Main Application - Pseudo-Code
## File: main.rs

```pseudo
IMPORT libraries:
    - clap (command-line argument parsing)
    - dialoguer (interactive user prompts)
    - indicatif (progress bars)
    - tokio (asynchronous runtime)
    - url (URL parsing and manipulation)
    - colored (for colored terminal output)

IMPORT modules:
    - crawler (web crawling)
    - dir_scanner (directory scanning)
    - form (form data structures)
    - reporter (report generation)
    - xss (XSS vulnerability scanner)
    - dependency_manager (external tool management)
    - file_inclusion_scanner (LFI/RFI scanner)
    - sql_injection_scanner (SQL injection scanner)
    - animation (startup animation)
    - bypass_403 (403/401 bypass scanner)
    - rate_limiter (rate limiting)

STRUCTURE Config:
    FIELDS:
        request_delay: Duration

STRUCTURE CommandLineInterface:
    FIELDS:
        target: Optional<String>
        target_list: Optional<String>
        scanner: Optional<String>
        wordlist: Optional<String>
        force_install: Boolean

FUNCTION configure_rate_limit() -> Config:
    DESCRIPTION: Configures the rate limit for requests per second (RPS).
    PROCESS:
        LOOP:
            PROMPT user for RPS (default "5")
            VALIDATE input is a number
            IF RPS is 0, print error and continue
            IF RPS > 100, cap at 100 and print warning
            PRINT current RPS
            IF RPS > 5, print warning about IP blacklisting
            CALCULATE delay_ms = 1000 / RPS
            RETURN Config with request_delay

ASYNC FUNCTION crawl_target(url, progress_manager, progress_style, rate_limiter) -> Result<(Vec<Url>, Vec<form::Form>), reqwest::Error>:
    DESCRIPTION: Crawls the target website to discover URLs and forms.
    PROCESS:
        CREATE new crawler with url and rate_limiter
        CREATE and configure progress bar
        CALL crawler.crawl()
        HANDLE result and return Ok or Err

ASYNC FUNCTION main():
    DESCRIPTION: Main entry point of the application.
    PROCESS:
        RUN intro animation
        PARSE CLI arguments
        CONFIGURE rate limit
        CREATE rate limiter
        GET target URLs from --target or --target_list argument, or prompt user
        GET concurrency level if --target_list is used
        CREATE semaphore with concurrency level
        CREATE vector for tasks
        FOR each target_url:
            SPAWN a new async task:
                ACQUIRE semaphore permit
                CALL run_scan with CLI args, rate_limiter, and target_url
        AWAIT all tasks to complete

ASYNC FUNCTION run_scan(cli, rate_limiter, target_url):
    DESCRIPTION: Runs the selected scanner on a single target.
    PROCESS:
        DETERMINE scanner selection from CLI argument or user prompt
        INITIALIZE multi-progress bar
        PARSE target_url into a Url object, handle errors
        CREATE reporter
        SWITCH selection:
            CASE 0 (XSS):
                CRAWL target to get URLs and forms
                CREATE XssScanner
                CREATE and configure progress bar
                CALL scanner.scan()
                HANDLE result
            CASE 1 (Open Directory):
                CHECK if feroxbuster is installed, prompt to install if needed
                CREATE DirScanner
                CREATE and configure progress bar
                CALL dir_scanner.scan()
                HANDLE result
            CASE 2 (File Inclusion):
                CRAWL target to get URLs and forms
                CREATE FileInclusionScanner
                CREATE and configure progress bar
                CALL scanner.scan()
                HANDLE result
            CASE 3 (SQL Injection):
                CRAWL target to get URLs and forms
                CREATE SqlInjectionScanner
                CREATE and configure progress bar
                CALL scanner.scan()
                HANDLE result
            CASE 4 (403/401 Bypass):
                CREATE BypassScanner
                CREATE and configure progress bar
                CALL bypass_scanner.scan()
                HANDLE result

FUNCTION read_lines(filename) -> io::Result<Vec<String>>:
    DESCRIPTION: Reads lines from a file into a vector of strings.
    PROCESS:
        OPEN file
        READ lines into a vector
        RETURN vector
```

## Key Design Patterns

```pseudo
PATTERN: Command Pattern
    - CLI arguments map to scanner commands
    - Modular scanner selection

PATTERN: Strategy Pattern
    - Different scanning strategies (XSS, SQLi, LFI, Directory, 403 Bypass)
    - Interchangeable at runtime

PATTERN: Concurrency
    - Tokio and Semaphores are used to handle multiple targets concurrently.

ERROR HANDLING:
    - Graceful degradation on errors
    - User-friendly error messages
    - Progress tracking even during failures
```