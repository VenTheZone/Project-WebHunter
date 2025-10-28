use std::process::{Command, Stdio};

pub fn is_feroxbuster_installed() -> bool {
    Command::new("feroxbuster")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub async fn install_feroxbuster() -> Result<(), Box<dyn std::error::Error>> {
    let child = Command::new("cargo")
        .arg("install")
        .arg("feroxbuster")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let output = child.wait_with_output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into())
    }
}
