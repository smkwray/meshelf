@echo off
setlocal
cd /d "%~dp0\.."
call scripts\rust-env.bat || exit /b 1
if "%RUST_LOG%"=="" set RUST_LOG=meshelf=debug,info
cargo run -p meshelf-desktop
