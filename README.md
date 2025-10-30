# WebHunter

WebHunter is a command-line tool for ethical hacking, designed to find common vulnerabilities in websites. It is written in Rust and provides a simple, interactive interface for running various scanning modules.

## Features

- **XSS Scanner:** Scans a website for reflected and stored Cross-Site Scripting (XSS) vulnerabilities in both URL parameters and HTML forms.
- **Open Directory Scanner:** Scans a website for open directories and sensitive files using a comprehensive, built-in wordlist based on SecLists' `raft-large` collections. This scanner is powered by `feroxbuster`.
- **File Inclusion Scanner:** Scans for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities by injecting a variety of payloads into URL parameters and form inputs.
- **SQL Injection Scanner:** Scans for error-based, boolean-based, and time-based SQL injection vulnerabilities in both URL parameters and HTML forms.

## Installation

1.  **Install Rust:** If you don't already have Rust installed, you can install it using `rustup`:
    ```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2.  **Build WebHunter:**
    ```
    git clone https://github.com/VenTheZone/Project-WebHunter.git
    cd webhunter
    cargo build --release
    ```

## Usage

You can run WebHunter in interactive mode by running it without any arguments:

```
./target/release/webhunter
```

This will present you with a series of prompts to enter the target URL and choose a scanner.

If you select the "Open Directory Scanner" and do not have `feroxbuster` installed, the tool will offer to install it for you.

You can also run WebHunter in non-interactive mode by providing the target URL and scanner type as command-line arguments:

```
./target/release/webhunter --target <target-url> --scanner <scanner-type>
```

### Scanners

-   `xss`: **Cross-Site Scripting Scanner.** This scanner crawls the target website to find all links and forms. It then injects a variety of payloads to test for reflected and stored XSS vulnerabilities.
-   `dir`: **Open Directory Scanner.** This scanner uses `feroxbuster` to search for open directories and sensitive files. It uses a default wordlist, but you can specify a custom one with the `--wordlist` option.
-   `file`: **File Inclusion Scanner.** This scanner tests for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities. It injects payloads into URL parameters and form inputs and looks for specific patterns in the response that indicate a successful inclusion.
-   `sql`: **SQL Injection Scanner.** This scanner tests for error-based, boolean-based, and time-based SQL injection vulnerabilities. It injects payloads into URL parameters and form inputs and analyzes the server's response to detect potential vulnerabilities.

### Options

-   `--wordlist <path>`: Specifies a custom wordlist to use with the Open Directory scanner. If not provided, a comprehensive default wordlist is used.

## Output

All scan reports are saved in a directory named after the target domain, with dots replaced by underscores. For example, if you scan `http://testphp.vulnweb.com/`, the reports will be saved in the `testphp_vulnweb_com` directory.

The following report files are generated:

-   **XSS Scanner:** `XSS-output.md`
-   **Open Directory Scanner:** `Open-Directories-output.md`
-   **File Inclusion Scanner:** `File-Inclusion-output.txt`
-   **SQL Injection Scanner:** `Sql-Injection-output.md`
