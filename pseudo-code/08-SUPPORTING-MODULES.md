# Supporting Modules - Pseudo-Code

## File: form.rs

```pseudo
STRUCTURE FormInput:
    DESCRIPTION: Represents a single form input element
    
    FIELDS:
        name: String        // Input name attribute
        value: String       // Input value (default or empty)
    
    DERIVES:
        Debug, Clone


STRUCTURE Form:
    DESCRIPTION: Represents an HTML form with its properties
    
    FIELDS:
        action: String              // Form action URL (may be relative)
        method: String              // HTTP method (GET or POST)
        inputs: Vector<FormInput>   // All form inputs
        url: URL                    // Page URL where form was found
    
    DERIVES:
        Debug, Clone
```

---

## File: dependency_manager.rs

```pseudo
IMPORT libraries:
    - std::process (command execution)


FUNCTION is_feroxbuster_installed():
    DESCRIPTION: Checks if feroxbuster is installed on the system
    
    OUTPUT:
        Boolean indicating if feroxbuster is available
    
    ALGORITHM:
        TRY:
            EXECUTE command "feroxbuster --version"
            SUPPRESS stdout (redirect to null)
            SUPPRESS stderr (redirect to null)
            
            CHECK if command completed successfully
            RETURN true if success
        CATCH:
            RETURN false


ASYNC FUNCTION install_feroxbuster():
    DESCRIPTION: Installs feroxbuster using cargo
    
    OUTPUT:
        Result indicating success or error with message
    
    ALGORITHM:
        TRY:
            SPAWN process "cargo install feroxbuster"
            PIPE stdin (for interactive prompts)
            PIPE stdout (to capture output)
            PIPE stderr (to capture errors)
            
            WAIT for process to complete
            STORE output
            
            IF process succeeded:
                RETURN Ok(())
            ELSE:
                GET error message from stderr
                RETURN Err(error_message)
        CATCH error:
            RETURN Err(error)
```

---

## File: animation.rs

```pseudo
IMPORT libraries:
    - figlet_rs (ASCII art generation)
    - crossterm (terminal manipulation)
    - rand (random number generation)
    - std::io (terminal detection)
    - std::thread::sleep (delays)


FUNCTION glitch_effect(stdout, text, font):
    DESCRIPTION: Creates a glitch animation effect on ASCII art
    
    INPUT:
        stdout: Terminal output handle
        text: Text to glitch
        font: FIGfont for rendering
    
    ALGORITHM:
        INITIALIZE random number generator
        CONVERT text to ASCII art using font
        SPLIT art into lines
        GET height = number of lines
        
        // Apply glitch effect 10 times
        REPEAT 10 times:
            SELECT random line (y coordinate)
            SELECT random length
            SELECT random start position
            
            // Generate glitchy characters
            CREATE glitch_text by:
                TAKE substring of line
                RANDOMLY replace characters
            
            // Display glitch
            MOVE cursor to random position
            PRINT glitch_text in green color
            FLUSH output
            SLEEP for random 10-30ms
            
            // Erase glitch
            MOVE cursor back to same position
            PRINT spaces to clear glitch
            FLUSH output


FUNCTION run_animation():
    DESCRIPTION: Displays animated WebHunter banner on startup
    
    ALGORITHM:
        // Check if running in terminal
        IF NOT running in terminal:
            PRINT "Welcome to WebHunter!"
            PRINT "by VenTheZone"
            RETURN
        
        // Initialize
        LOAD standard FIGfont
        SET webhunter_text = "WebHunter"
        SET author_text = "by VenTheZone"
        GET stdout handle
        
        // Clear screen
        TRY:
            CLEAR entire terminal
        CATCH:
            PRINT "Welcome to WebHunter!"
            PRINT "by VenTheZone"
            RETURN
        
        // Apply glitch effect
        CALL glitch_effect(stdout, webhunter_text, font)
        
        // Convert text to ASCII art
        CONVERT webhunter_text to ASCII art
        SPLIT into lines of characters
        
        // Calculate dimensions
        GET height = number of lines
        GET width = maximum line length
        
        // Collect all non-space characters with positions
        INITIALIZE chars_to_draw as empty Vector
        
        FOR y FROM 0 TO height - 1:
            FOR x FROM 0 TO width - 1:
                IF character is not space:
                    ADD (x, y, character) to chars_to_draw
        
        // Sort for diagonal "3D pop-out" effect
        SORT chars_to_draw by (x + y)
        
        // Render with diagonal animation
        FOR EACH (x, y, character) IN chars_to_draw:
            TRY:
                MOVE cursor to (x, y)
                PRINT character in green color
                FLUSH output
                SLEEP for 2 milliseconds
            CATCH:
                BREAK loop
        
        // Display author name
        CALCULATE author_row = height
        CALCULATE author_col = width - length(author_text)
        IF author_col < 0:
            SET author_col = 0
        
        TRY:
            MOVE cursor to (author_col, author_row)
            
            FOR EACH character IN author_text:
                PRINT character in dark green
                FLUSH output
                SLEEP for 50 milliseconds
        CATCH:
            // Fallback
            PRINT author_text
        
        // Position cursor for next output
        MOVE cursor to (0, author_row + 2)
        
        // Display instructions
        PRINT "\nUse the arrow keys to navigate ↑ ↓"
        SLEEP for 200 milliseconds
```

## Animation Details

```pseudo
ASCII_ART_GENERATION:
    Tool: figlet_rs
    Font: Standard FIGfont
    
    Example Output:
        __        __   _     _   _             _            
        \ \      / /__| |__ | | | |_   _ _ __ | |_ ___ _ __ 
         \ \ /\ / / _ \ '_ \| |_| | | | | '_ \| __/ _ \ '__|
          \ V  V /  __/ |_) |  _  | |_| | | | | ||  __/ |   
           \_/\_/ \___|_.__/|_| |_|\__,_|_| |_|\__\___|_|


GLITCH_EFFECT:
    Purpose: Eye-catching startup animation
    Duration: ~300-500ms
    Iterations: 10 glitch flashes
    Colors: Green (main), Dark Green (author)
    
    Mechanism:
        1. Select random portion of ASCII art
        2. Replace with random characters
        3. Display briefly (10-30ms)
        4. Erase
        5. Repeat


DIAGONAL_RENDERING:
    Purpose: Creates "3D pop-out" effect
    Method: Sort by (x + y) coordinate sum
    Speed: 2ms per character
    
    Visual Effect:
        Characters appear from top-left to bottom-right
        Creates illusion of depth
        Fast enough to be smooth (2ms delay)


TERMINAL_COMPATIBILITY:
    Detection: stdout().is_terminal()
    Fallback: Plain text if not in terminal
    Cross-platform: Works on Linux, macOS, Windows
    
    Requirements:
        - Terminal with ANSI color support
        - Cursor positioning support
        - Clear screen support


COLOR_SCHEME:
    Primary: Green (cybersecurity/hacker aesthetic)
    Secondary: Dark Green (subtle contrast)
    Theme: Matrix-inspired terminal look
```

## Error Handling

```pseudo
GRACEFUL_DEGRADATION:
    
    Non-Terminal Environment:
        - Detect with is_terminal()
        - Skip animation
        - Show plain text welcome
    
    Terminal Clear Failure:
        - Catch error
        - Skip animation
        - Show plain text
    
    Cursor Movement Failure:
        - Break animation loop
        - Continue to next section
        - Terminal may not support ANSI codes
    
    Font Loading Failure:
        - Use fallback text
        - No ASCII art
        - Still functional


PERFORMANCE:
    Total Animation Time: ~1-2 seconds
    - Glitch effect: 300-500ms
    - Diagonal render: 500-1000ms (depends on text size)
    - Author name: 500-700ms
    
    CPU Usage: Minimal
    Memory Usage: Small (ASCII art strings)
    
    User Experience:
        - Fast enough to be engaging
        - Not annoyingly long
        - Skippable (user can Ctrl+C)
```

## Module Interdependencies

```pseudo
DEPENDENCY_GRAPH:
    
    form.rs:
        - Used by: crawler.rs, xss.rs, sql_injection_scanner.rs, 
                   file_inclusion_scanner.rs
        - Depends on: url (standard library)
        - Purpose: Shared data structures
    
    dependency_manager.rs:
        - Used by: main.rs (for feroxbuster installation)
        - Depends on: std::process
        - Purpose: External tool management
    
    animation.rs:
        - Used by: main.rs (startup only)
        - Depends on: figlet_rs, crossterm, rand
        - Purpose: User experience enhancement
        - Optional: Can be disabled without affecting functionality
```

## Design Patterns

```pseudo
DATA_STRUCTURES (form.rs):
    Pattern: Plain Old Data (POD)
    Benefits:
        - Simple serialization
        - Easy cloning
        - Thread-safe (if needed)
        - No complex lifecycle


DEPENDENCY_MANAGEMENT (dependency_manager.rs):
    Pattern: Facade
    Benefits:
        - Hides complexity of cargo installation
        - Simple boolean check interface
        - Easy to extend for other tools


ANIMATION (animation.rs):
    Pattern: Template Method
    Benefits:
        - Consistent animation structure
        - Easy to modify effects
        - Graceful fallbacks
        - Separation of concerns
```

## Testing Considerations

```pseudo
TESTABILITY:
    
    form.rs:
        - Pure data structures
        - Easy to create test instances
        - No external dependencies
    
    dependency_manager.rs:
        - Mock process execution
        - Test with/without feroxbuster
        - Test installation success/failure
    
    animation.rs:
        - Test non-terminal mode
        - Test terminal mode (manual)
        - Test error handling
        - Skip in CI/CD (no TTY)


MOCKING_STRATEGY:
    dependency_manager.rs:
        - Mock Command::new() for testing
        - Simulate installed/not installed states
        - Simulate installation failures
    
    animation.rs:
        - Test in non-terminal mode automatically
        - Manual testing for visual verification
        - Check fallback behavior
```
