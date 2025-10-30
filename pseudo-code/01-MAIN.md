# Main Application - Pseudo-Code
## File: main.rs

```pseudo
IMPORT libraries:
    - clap (command-line argument parsing)
    - dialoguer (interactive user prompts)
    - indicatif (progress bars)
    - url (URL parsing and manipulation)

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


STRUCTURE CommandLineInterface:
    FIELDS:
        target: Optional<String>           // Target URL
        scanner: Optional<String>          // Scanner type
        wordlist: Optional<String>         // Custom wordlist path
        force_install: Boolean             // Force tool installation


ASYNC FUNCTION crawl_target(url, progress_manager, progress_style):
    DESCRIPTION: Crawls the target website to discover URLs and forms
    
    INPUT:
        url: URL object
        progress_manager: MultiProgress manager
        progress_style: ProgressStyle template
    
    OUTPUT:
        Result containing (Vector<URL>, Vector<Form>) or Error
    
    PROCESS:
        CREATE new crawler with target URL
        CREATE progress bar with given style
        ADD progress bar to manager
        
        TRY:
            CALL crawler.crawl() with progress bar
            STORE results as (urls, forms)
            SET progress bar message "Crawling complete"
            RETURN Ok((urls, forms))
        CATCH error:
            SET progress bar message "Crawling failed: {error}"
            PRINT error message to stderr
            RETURN Err(error)


ASYNC FUNCTION main():
    DESCRIPTION: Main entry point of the application
    
    PROCESS:
        SET environment variable RUST_BACKTRACE to "full"
        
        // Display startup animation
        CALL run_animation()
        
        // Parse command-line arguments
        PARSE CommandLineInterface from arguments
        
        // Get target URL
        IF target is provided via CLI:
            SET target_url = provided target
        ELSE:
            PROMPT user "Enter the target website URL"
            IF prompt fails:
                PRINT "Could not read target URL. Use --target argument."
                EXIT
            SET target_url = prompted value
        
        // Get scanner selection
        IF scanner is provided via CLI:
            MAP scanner string to selection index:
                "xss" → 0
                "dir" → 1
                "file" → 2
                "sql" → 3
        ELSE:
            PROMPT user with options:
                [0] "XSS"
                [1] "Open Directory"
                [2] "File Inclusion"
                [3] "SQL Injection"
            IF prompt fails:
                PRINT "Could not read selection. Use --scanner argument."
                EXIT
            SET selection = user's choice
        
        // Initialize progress tracking
        CREATE multi-progress manager
        CREATE progress style with template:
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] 
             {bytes}/{total_bytes} ({eta}) {msg}"
        SET progress characters "#>-"
        
        // Parse and validate URL
        TRY:
            PARSE target_url string into URL object
        CATCH RelativeUrlWithoutBase:
            PRINT "Error: Invalid URL. Please provide absolute URL (e.g., http://example.com)"
            EXIT
        CATCH other parse error:
            PRINT "Error: Invalid URL: {error}"
            EXIT
        
        
        // Execute selected scanner
        SWITCH selection:
            
            CASE 0 (XSS Scanner):
                // Crawl the target
                TRY:
                    CALL crawl_target(url, progress_manager, progress_style)
                    STORE as (found_urls, found_forms)
                CATCH:
                    EXIT
                
                // Initialize XSS scanner
                CREATE xss_scanner with found_urls and found_forms
                
                // Calculate total payloads
                CALCULATE total_tests = (urls * payload_count) + (forms * payload_count)
                CREATE progress bar with total_tests
                SET progress bar style
                ADD progress bar to manager
                
                // Run scan
                TRY:
                    CALL scanner.scan() with progress bar
                    STORE vulnerabilities
                    SET progress bar message "Scanning complete"
                    
                    IF no vulnerabilities found:
                        PRINT "No XSS vulnerabilities found."
                    ELSE:
                        PRINT "Found {count} XSS vulnerabilities:"
                        CREATE reporter
                        TRY:
                            CALL reporter.report(vulnerabilities, url)
                            CALCULATE domain_name = url.domain replace "." with "_"
                            PRINT "Report saved to {domain_name}/XSS-output.md"
                        CATCH error:
                            PRINT "Error writing report: {error}"
                CATCH error:
                    SET progress bar message "Scanning failed: {error}"
                    PRINT "Error scanning for XSS: {error}"
            
            
            CASE 1 (Open Directory Scanner):
                // Check if feroxbuster is installed
                IF force_install OR NOT is_feroxbuster_installed():
                    IF force_install:
                        SET confirm = 0  // Yes
                    ELSE:
                        PROMPT "Feroxbuster is not installed. Install it now?"
                        OPTIONS: ["Yes", "No"]
                        SET confirm = user's choice
                    
                    IF confirm == 0:  // Yes
                        CREATE spinner progress bar
                        SET message "Installing feroxbuster..."
                        ADD to progress manager
                        
                        TRY:
                            CALL install_feroxbuster()
                            SET message "Feroxbuster installed successfully"
                        CATCH error:
                            SET message "Failed to install feroxbuster: {error}"
                            EXIT
                    ELSE:
                        PRINT "Feroxbuster is required for Open Directory Scanner."
                        EXIT
                
                // Run directory scan
                CREATE spinner progress bar
                SET progress bar style
                ADD to progress manager
                
                CREATE dir_scanner with url, progress_bar, wordlist
                
                TRY:
                    CALL dir_scanner.scan()
                    STORE found_dirs
                    SET progress bar message "Directory scan complete"
                    
                    IF no directories found:
                        PRINT "No open directories found."
                    ELSE:
                        PRINT "Found {count} open directories:"
                        CREATE reporter
                        SET wordlist_name = wordlist OR "default_wordlist.txt"
                        
                        TRY:
                            CALL reporter.report_dirs(found_dirs, url, wordlist_name)
                            CALCULATE domain_name = url.domain replace "." with "_"
                            PRINT "Report saved to {domain_name}/Open-Directories-output.md"
                        CATCH error:
                            PRINT "Error writing report: {error}"
                CATCH error:
                    SET progress bar message "Directory scan failed: {error}"
                    PRINT "Error scanning for directories: {error}"
            
            
            CASE 2 (File Inclusion Scanner):
                // Crawl the target
                TRY:
                    CALL crawl_target(url, progress_manager, progress_style)
                    STORE as (found_urls, found_forms)
                CATCH:
                    EXIT
                
                // Initialize file inclusion scanner
                CREATE file_inclusion_scanner with found_urls and found_forms
                
                // Calculate total tests
                CALCULATE total_tests = (urls * payload_count) + (forms * payload_count)
                CREATE progress bar with total_tests
                SET progress bar style
                ADD progress bar to manager
                
                // Run scan
                TRY:
                    CALL scanner.scan() with progress bar
                    STORE vulnerabilities
                    SET progress bar message "Scanning complete"
                    
                    IF no vulnerabilities found:
                        PRINT "No file inclusion vulnerabilities found."
                    ELSE:
                        PRINT "Found {count} file inclusion vulnerabilities:"
                        CREATE reporter
                        
                        TRY:
                            CALL reporter.report_file_inclusion(vulnerabilities, url)
                            CALCULATE domain_name = url.domain replace "." with "_"
                            PRINT "Report saved to {domain_name}/File-Inclusion-output.txt"
                        CATCH error:
                            PRINT "Error writing report: {error}"
                CATCH error:
                    SET progress bar message "Scanning failed: {error}"
                    PRINT "Error scanning for file inclusion: {error}"
            
            
            CASE 3 (SQL Injection Scanner):
                // Crawl the target
                TRY:
                    CALL crawl_target(url, progress_manager, progress_style)
                    STORE as (found_urls, found_forms)
                CATCH:
                    EXIT
                
                // Initialize SQL injection scanner
                CREATE sql_injection_scanner with found_urls and found_forms
                
                // Calculate total tests
                CALCULATE total_tests = (urls * payload_count) + (forms * payload_count)
                CREATE progress bar with total_tests
                SET progress bar style
                ADD progress bar to manager
                
                // Run scan
                TRY:
                    CALL scanner.scan() with progress bar
                    STORE vulnerabilities
                    SET progress bar message "Scanning complete"
                    
                    IF no vulnerabilities found:
                        PRINT "No SQL injection vulnerabilities found."
                    ELSE:
                        PRINT "Found {count} SQL injection vulnerabilities:"
                        CREATE reporter
                        
                        TRY:
                            CALL reporter.report_sql_injection(vulnerabilities, url)
                            CALCULATE domain_name = url.domain replace "." with "_"
                            PRINT "Report saved to {domain_name}/Sql-Injection-output.txt"
                        CATCH error:
                            PRINT "Error writing report: {error}"
                CATCH error:
                    SET progress bar message "Scanning failed: {error}"
                    PRINT "Error scanning for SQL injection: {error}"
    
    END main
```

## Key Design Patterns

```pseudo
PATTERN: Command Pattern
    - CLI arguments map to scanner commands
    - Modular scanner selection

PATTERN: Strategy Pattern
    - Different scanning strategies (XSS, SQLi, LFI, Directory)
    - Interchangeable at runtime

PATTERN: Template Method
    - Common workflow: crawl → scan → report
    - Specific implementation in each scanner

ERROR HANDLING:
    - Graceful degradation on errors
    - User-friendly error messages
    - Progress tracking even during failures
```
