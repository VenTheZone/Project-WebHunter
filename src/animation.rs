use crossterm::{cursor, terminal, ExecutableCommand, style::{Stylize, Color}};
use rand::Rng;
use std::io::{stdout, IsTerminal, Write};
use std::thread;
use std::time::Duration;

pub fn run_intro_animation() {
    if !stdout().is_terminal() {
        println!("Welcome to WebHunter!");
        println!("by VenTheZone");
        return;
    }

    const TITLE: &str = r#"
  _      __    __     __ __          __         
 | | /| / /__ / /    / // /_ _____  / /____ ____
 | |/ |/ / -_) _ \  / _  / // / _ \/ __/ -_) __/
 |__/|__/\__/_.__/ /_//_/\_,_/_//_/\__/\__/_/   

"#;
    const AUTHOR: &str = "by VenTheZone";

    let mut stdout = stdout();
    let mut rng = rand::thread_rng();

    stdout.execute(cursor::Hide).unwrap();
    stdout.execute(terminal::Clear(terminal::ClearType::All)).unwrap();

    let lines: Vec<&str> = TITLE.lines().filter(|&l| !l.trim().is_empty()).collect();
    let final_chars: Vec<Vec<char>> = lines.iter().map(|line| line.chars().collect()).collect();

    let height = final_chars.len();
    let width = final_chars.iter().map(|v| v.len()).max().unwrap_or(0);

    let mut current_chars = vec![vec![' '; width]; height];

    // Animation loop to build the title
    for _ in 0..30 { // Number of frames
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        let mut all_match = true;

        for y in 0..height {
            for x in 0..width {
                // Check if the final design has a character at this position
                if x >= final_chars[y].len() || final_chars[y][x] == ' ' {
                    if current_chars[y][x] != ' ' {
                        current_chars[y][x] = ' ';
                    }
                    print!(" ");
                    continue;
                }

                let final_char = final_chars[y][x];

                if current_chars[y][x] == final_char {
                    print!("{}", final_char.to_string().green());
                    continue;
                }

                all_match = false;
                if rng.gen_bool(0.25) {
                    current_chars[y][x] = final_char;
                    print!("{}", final_char.to_string().green());
                } else {
                    let glitch_chars = ['#', '*', '%', '&', '$', '.'];
                    let random_char = glitch_chars[rng.gen_range(0..glitch_chars.len())];
                    print!("{}", random_char.to_string().with(Color::DarkGrey));
                }
            }
            println!();
        }

        if all_match {
            break;
        }

        stdout.flush().unwrap();
        thread::sleep(Duration::from_millis(50));
    }

    // Ensure the final title is printed correctly
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    for line in &lines {
        println!("{}", line.green());
    }

    // Print author and wait
    let author_line = (lines.len() + 1) as u16;
    stdout.execute(cursor::MoveTo(0, author_line)).unwrap();
    println!("{}", AUTHOR.with(Color::DarkGreen));

    stdout.execute(cursor::Show).unwrap();
    stdout.flush().unwrap();
    thread::sleep(Duration::from_millis(500));

    // Move cursor below the art to prepare for the menu
    stdout.execute(cursor::MoveTo(0, author_line + 2)).unwrap();
    stdout.flush().unwrap();
}
