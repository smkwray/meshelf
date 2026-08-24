@echo off
setlocal
cd /d "%~dp0\.."
call scripts\rust-env.bat || exit /b 1
py -3 scripts\verify-repo.py --allow-stale-manifest || python scripts\verify-repo.py --allow-stale-manifest || exit /b 1
cargo fmt --all -- --check || exit /b 1
cargo check --workspace --all-targets || exit /b 1
cargo clippy --workspace --all-targets -- -D warnings || exit /b 1
cargo test --workspace --all-targets || exit /b 1
cargo run -p meshelf-sim || exit /b 1
echo All source gates passed on this host. Record the exact receipt in status\.
