# 403/401 Bypass Scanner (`bypass_403.rs`)

This document outlines the pseudo-code and logic for the 403/401 Bypass Scanner module in WebHunter.

## Overview

The 403/401 Bypass Scanner is designed to test for common misconfigurations and vulnerabilities that allow access to resources that are otherwise forbidden (returning a 403 Forbidden or 401 Unauthorized status code).

When a bypass is successfully identified, the scanner immediately:
1.  Prints a "fancy" verbose output to the console with details of the bypass.
2.  Takes both an HTML and a PNG snapshot of the successfully accessed page.
3.  Records the finding to be included in the final Markdown report.

## Data Structures

### `BypassBypass` Struct

Represents a single successful bypass finding.

```rust
struct BypassBypass {
    url: Url,              // The original URL that returned a 403
    bypass_url: Url,       // The URL used to successfully bypass the restriction
    method: String,        // The HTTP method used (e.g., "GET", "POST")
    technique: String,     // The technique used (e.g., "URL Encoding %2e", "Custom Header (X-Forwarded-For)")
    response_size: u64,
    severity: String,
}
```

## Core Logic (`BypassScanner`)

### `scan()`

The main entry point for the scanner.

```
FUNCTION scan(target_url):
  INITIALIZE bypasses_list

  // 1. Load a list of common administrative directories/paths
  directories = load_directories_from_wordlist()

  // 2. Iterate through each directory
  FOR each directory in directories:
    test_url = target_url + "/" + directory

    // 3. Check the status of the original URL
    response = HTTP_GET(test_url)
    IF response.status_code == 403:
      // 4. If forbidden, attempt bypass techniques
      bypass_result = try_bypass_directory(test_url, directory)
      IF bypass_result is not None:
        ADD bypass_result to bypasses_list
    END IF
  END FOR

  // 5. Run a comprehensive set of header-based bypasses on the root URL
  header_bypasses = test_comprehensive_bypass(target_url)
  ADD header_bypasses to bypasses_list

  RETURN bypasses_list
END FUNCTION
```

### `try_bypass_directory()`

Attempts various URL manipulation and HTTP method techniques on a specific path.

```
FUNCTION try_bypass_directory(original_url, directory):
  // 1. Generate a list of bypass variations
  techniques = generate_bypass_techniques(original_url, directory)
  // (e.g., "admin" -> "admin/.", "admin/%2e", "admin.html")

  // 2. Test URL-based techniques
  FOR each (technique_url, technique_name) in techniques:
    response = HTTP_GET(technique_url)

    // 3. Check for a successful bypass
    IF response.status_code is successful (e.g., 200 OK):
      bypass = CREATE_BypassBypass_struct(...)

      // 4. Trigger verbose output and snapshot
      print_fancy_bypass(bypass)
      snapshot.take_snapshot(bypass_url, ...) // Non-blocking call

      RETURN bypass
    END IF
  END FOR

  // 5. Test different HTTP methods (POST, PUT, etc.)
  FOR each method in ["POST", "PUT", ...]:
    response = HTTP_REQUEST(original_url, method)
    IF response.status_code is successful:
      // Create bypass, print output, take snapshot...
      RETURN bypass
    END IF
  END FOR

  RETURN None
END FUNCTION
```

### `test_comprehensive_bypass()`

Attempts to bypass restrictions on a given URL using a wide range of custom headers and user-agent strings.

```
FUNCTION test_comprehensive_bypass(target_url):
  // 1. Define lists of common bypass headers and user agents
  user_agents = ["Googlebot/2.1", "admin", ...]
  headers = [("X-Forwarded-For", "127.0.0.1"), ("X-Original-URL", "/"), ...]

  // 2. Iterate through all combinations
  FOR each header in headers:
    FOR each user_agent in user_agents:
      response = HTTP_GET(target_url, headers={header}, user_agent=user_agent)

      // 3. Check for a successful bypass
      IF response.status_code is successful:
        bypass = CREATE_BypassBypass_struct(...)

        // 4. Trigger verbose output and snapshot
        print_fancy_bypass(bypass)
        snapshot.take_snapshot(bypass_url, ...) // Non-blocking call

        ADD bypass to bypasses_list
        BREAK from user_agent loop (one success per header is enough)
      END IF
    END FOR
  END FOR

  RETURN bypasses_list
END FUNCTION
```
