@echo off
setlocal
cd /d "%~dp0\.."
where rustup >nul 2>nul || (
  echo ERROR: rustup is required because rust-toolchain.toml pins the project toolchain.
  exit /b 1
)
rustup toolchain install 1.92.0 --profile minimal --component rustfmt --component clippy || exit /b 1
call scripts\rust-env.bat || exit /b 1
cargo fetch || exit /b 1
py -3 scripts\verify-repo.py --allow-stale-manifest || python scripts\verify-repo.py --allow-stale-manifest || exit /b 1
echo Bootstrap complete. Run scripts\check.bat next.
