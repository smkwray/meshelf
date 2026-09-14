@echo off
setlocal
cd /d "%~dp0\.."
call scripts\rust-env.bat || exit /b 1
cargo run -p meshelf-sim
