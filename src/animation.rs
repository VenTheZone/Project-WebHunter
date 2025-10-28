use figlet_rs::FIGfont;
use std::io::{stdout, Write, IsTerminal};
use std::thread::sleep;
use std::time::Duration;
use crossterm::{cursor, terminal, ExecutableCommand, style::{Stylize, Color}};
use rand::Rng;

fn glitch_effect(stdout: &mut std::io::Stdout, text: &str, font: &FIGfont) {
    let mut rng = rand::rngs::ThreadRng::default();
    let figure = font.convert(text).unwrap().to_string();
    let lines: Vec<&str> = figure.lines().collect();
    let height = lines.len() as u16;

    for _ in 0..10 {
        let y = rng.gen_range(0..height);
        let len = rng.gen_range(1..lines[y as usize].len() / 2);
        let start = rng.gen_range(0..lines[y as usize].len() - len);
        let glitch_text: String = lines[y as usize]
            .chars()
            .skip(start)
            .take(len)
            .map(|_| if rng.gen() { rng.gen::<char>() } else { ' ' })
            .collect();

        stdout.execute(cursor::MoveTo(rng.gen_range(0..5), y)).ok();
        print!("{}", glitch_text.clone().with(Color::Green));
        stdout.flush().ok();
        sleep(Duration::from_millis(rng.gen_range(10..30)));

        stdout.execute(cursor::MoveTo(rng.gen_range(0..5), y)).ok();
        print!("{}", " ".repeat(glitch_text.len()));
        stdout.flush().ok();
    }
}

pub fn run_animation() {
    if !stdout().is_terminal() {
        println!("Welcome to WebHunter!");
        println!("by VenTheZone");
        return;
    }

    let standard_font = FIGfont::standard().unwrap();
    let webhunter_text = "WebHunter";
    let author_text = "by VenTheZone";

    let mut stdout = stdout();

    if stdout.execute(terminal::Clear(terminal::ClearType::All)).is_err() {
        println!("Welcome to WebHunter!");
        println!("by VenTheZone");
        return;
    }

    glitch_effect(&mut stdout, webhunter_text, &standard_font);

    if let Some(figure) = standard_font.convert(webhunter_text) {
        let lines: Vec<Vec<char>> = figure
            .to_string()
            .lines()
            .map(|l| l.chars().collect())
            .collect();

        let height = lines.len();
        let width = lines.iter().map(|l| l.len()).max().unwrap_or(0);

        // Precompute all non-space character positions
        let mut chars_to_draw = Vec::new();
        for (y, line) in lines.iter().enumerate() {
            for (x, &ch) in line.iter().enumerate() {
                if ch != ' ' {
                    chars_to_draw.push((x, y, ch));
                }
            }
        }

        // Sort by (x + y) to create diagonal "3D pop-out" effect
        chars_to_draw.sort_by_key(|(x, y, _)| (*x as u32) + (*y as u32));

        // Fast diagonal render (feels 3D)
        for (x, y, ch) in chars_to_draw {
            if stdout.execute(cursor::MoveTo(x as u16, y as u16)).is_err() {
                break;
            }
            print!("{}", ch.to_string().with(Color::Green));
            stdout.flush().ok();
            sleep(Duration::from_millis(2)); // ultra-fast but smooth
        }

        // Author: right-aligned under figlet width
        let author_row = height as u16;
        let author_col = if width > author_text.len() {
            (width - author_text.len()) as u16
        } else {
            0
        };

        if stdout.execute(cursor::MoveTo(author_col, author_row)).is_ok() {
            for char in author_text.chars() {
                print!("{}", char.to_string().with(Color::DarkGreen));
                stdout.flush().ok();
                sleep(Duration::from_millis(50));
            }
        }

        // Move cursor to next line for clean prompt
        stdout.execute(cursor::MoveTo(0, author_row + 1)).ok();
    } else {
        println!("{}", webhunter_text);
        println!("{}", author_text);
    }

    sleep(Duration::from_millis(200)); // barely pause
}
