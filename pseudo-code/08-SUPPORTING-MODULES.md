# Supporting Modules - Pseudo-Code

## File: form.rs

```pseudo
STRUCTURE FormInput:
    FIELDS:
        name: String
        value: String

STRUCTURE Form:
    FIELDS:
        action: String
        method: String
        inputs: Vector<FormInput>
        url: URL
```

---

## File: dependency_manager.rs

```pseudo
FUNCTION is_feroxbuster_installed() -> bool:
    DESCRIPTION: Checks if feroxbuster is installed.
    PROCESS:
        EXECUTE "feroxbuster --version"
        RETURN true if successful, false otherwise.

ASYNC FUNCTION install_feroxbuster() -> Result<(), Box<dyn Error>>:
    DESCRIPTION: Installs feroxbuster using cargo.
    PROCESS:
        SPAWN "cargo install feroxbuster"
        AWAIT process completion.
        IF successful, RETURN Ok.
        ELSE, RETURN Err with stderr output.
```

---

## File: animation.rs

```pseudo
FUNCTION run_intro_animation():
    DESCRIPTION: Displays an animated title sequence.
    PROCESS:
        IF not in a terminal, PRINT plain text title and RETURN.
        HIDE cursor, CLEAR screen.
        DEFINE title and author strings.
        CONVERT title to a grid of characters.
        LOOP 30 times (frames):
            MOVE cursor to top-left.
            FOR each character in the grid:
                IF the final character is a space, PRINT space.
                IF current character matches final, PRINT final character (green).
                ELSE (not yet matched):
                    SET all_match = false.
                    IF random chance (25%), SET current to final and PRINT (green).
                    ELSE, PRINT a random glitch character (grey).
            IF all_match is true, BREAK loop.
            FLUSH output, SLEEP 50ms.
        ENSURE final title is printed correctly.
        PRINT author name.
        SHOW cursor, FLUSH output, SLEEP 500ms.
        MOVE cursor down to prepare for next output.
```

---

## File: rate_limiter.rs

```pseudo
STRUCTURE RateLimiter:
    FIELDS:
        delay: Duration
        last_request: Mutex<Instant>

FUNCTION RateLimiter::new(delay) -> RateLimiter:
    DESCRIPTION: Creates a new RateLimiter.

ASYNC FUNCTION RateLimiter::wait():
    DESCRIPTION: Waits for the specified delay since the last request.
    PROCESS:
        LOCK last_request mutex.
        CALCULATE time elapsed since last request.
        IF elapsed < delay, SLEEP for the remaining time.
        UPDATE last_request to current time.
```

---

## File: snapshot.rs

```pseudo
FUNCTION get_snapshot_filename_base(url, method, payload) -> String:
    DESCRIPTION: Creates a sanitized base filename for snapshots.
    PROCESS:
        SANITIZE path, method, and payload strings.
        RETURN formatted string.

ASYNC FUNCTION take_snapshot(url, domain, method, payload, body):
    DESCRIPTION: Takes an HTML and PNG snapshot of a given page body.
    PROCESS:
        SPAWN a blocking task:
            CREATE snapshots directory.
            GENERATE filename base.
            SAVE body to an HTML file.
            LAUNCH a headless browser.
            CREATE a new tab.
            CONSTRUCT a data URL with the HTML body and a base href.
            NAVIGATE to the data URL.
            CAPTURE a screenshot.
            SAVE screenshot as a PNG file.
            RETURN Ok.
```