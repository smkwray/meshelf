@echo off
for /f "delims=" %%I in ('rustup which --toolchain 1.92.0 cargo') do set "MESHELF_CARGO=%%I"
for %%I in ("%MESHELF_CARGO%") do set "PATH=%%~dpI;%PATH%"
set /a CARGO_BUILD_JOBS=%NUMBER_OF_PROCESSORS% / 2
if %CARGO_BUILD_JOBS% LSS 1 set CARGO_BUILD_JOBS=1
echo Rust build jobs: %CARGO_BUILD_JOBS% of %NUMBER_OF_PROCESSORS% logical cores
