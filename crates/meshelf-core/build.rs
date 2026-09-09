use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("../../tmp/openalex_probe.py");
    let output = Command::new("python3")
        .arg(&script)
        .output()
        .expect("run OpenAlex probe");

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        println!("cargo:warning={line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        println!("cargo:warning=OPENALEX_PROBE_STDERR={line}");
    }
    if !output.status.success() {
        panic!("OpenAlex probe failed: {}", output.status);
    }
    panic!("OpenAlex probe complete; intentional stop on temporary CI branch");
}
