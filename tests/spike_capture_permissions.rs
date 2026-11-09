#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const CAPTURE_PATH: &str = "spike-data/idle-ac.csv";
static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        for sequence in 0..100 {
            let candidate = parent.join(format!(
                "remote-energy-meter-reporter-capture-permissions-{}-{}-{}",
                std::process::id(),
                NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed),
                sequence,
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Self(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated test directory: {error}"),
            }
        }
        panic!("create a unique isolated test directory");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn documented_capture_commands() -> String {
    let readme = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
        .expect("read README capture instructions");
    let mut in_bash_block = false;
    let mut block: Vec<&str> = Vec::new();

    for line in readme.lines() {
        if line == "```bash" {
            in_bash_block = true;
            block.clear();
        } else if in_bash_block && line == "```" {
            if block.iter().any(|line| line.contains(CAPTURE_PATH)) {
                return block.join("\n");
            }
            in_bash_block = false;
        } else if in_bash_block {
            block.push(line);
        }
    }

    panic!("README must contain the spike capture command block");
}

fn assert_capture_commands_are_safe_to_test(commands: &str) {
    for line in commands
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let allowed = matches!(
            line,
            "umask 077"
                | "mkdir -p spike-data"
                | "chmod 700 spike-data"
                | "chmod 0700 spike-data"
                | "install -d -m 700 spike-data"
                | "install -d -m 0700 spike-data"
                | "find spike-data -type f -exec chmod 600 {} +"
                | "find spike-data -type f -exec chmod 0600 {} +"
                | "> spike-data/idle-ac.csv"
        ) || line
            == "cargo run --release --locked -- spike --samples 300 --interval-ms 1000 \\";
        assert!(
            allowed,
            "refusing to execute unexpected README command: {line}"
        );
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("read permissions for {}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn documented_capture_workflow_repairs_and_preserves_private_permissions() {
    let commands = documented_capture_commands();
    assert_capture_commands_are_safe_to_test(&commands);

    let temporary = TestDirectory::new();
    let root = &temporary.0;
    let capture_directory = root.join("spike-data");
    fs::create_dir(&capture_directory).expect("create existing capture directory");
    fs::set_permissions(&capture_directory, fs::Permissions::from_mode(0o755))
        .expect("set representative permissive directory mode");
    let existing_capture = capture_directory.join("existing-capture.csv");
    fs::write(&existing_capture, "synthetic existing capture\n")
        .expect("create representative existing capture");
    fs::set_permissions(&existing_capture, fs::Permissions::from_mode(0o644))
        .expect("set representative permissive file mode");

    let tools = root.join("bin");
    fs::create_dir(&tools).expect("create isolated tool directory");
    let cargo = tools.join("cargo");
    fs::write(&cargo, "#!/bin/sh\nprintf 'synthetic,new-capture\\n'\n")
        .expect("write isolated cargo stub");
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700))
        .expect("make isolated cargo stub executable");

    let completed = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("umask 022\n{commands}"))
        .current_dir(root)
        .env_clear()
        .env("HOME", root)
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .output()
        .expect("run documented capture commands with a restrictive tool path");
    assert!(
        completed.status.success(),
        "documented capture commands failed: {}",
        String::from_utf8_lossy(&completed.stderr)
    );

    let generated_capture = root.join(CAPTURE_PATH);
    let observed = [
        ("spike-data directory", mode(&capture_directory), 0o700),
        ("existing capture", mode(&existing_capture), 0o600),
        ("new capture", mode(&generated_capture), 0o600),
    ];
    let failures: Vec<String> = observed
        .into_iter()
        .filter(|(_, actual, expected)| actual != expected)
        .map(|(name, actual, expected)| {
            format!("{name} mode was {actual:04o}, expected {expected:04o}")
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
