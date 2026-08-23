use anyhow::Result;

fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("pair-stdio") {
        return meshelf_bootstrap::run_stdio();
    }
    anyhow::bail!("usage: meshelfctl pair-stdio")
}
