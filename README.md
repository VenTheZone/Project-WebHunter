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
    git clone <repository-url>
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

-   `xss`: Runs the XSS scanner.
-   `dir`: Runs the Open Directory scanner.
-   `file`: Runs the File Inclusion scanner.
-   `sql`: Runs the SQL Injection scanner.

### Options

-   `--wordlist <path>`: Specifies a custom wordlist to use with the Open Directory scanner. If not provided, a comprehensive default wordlist is used.
