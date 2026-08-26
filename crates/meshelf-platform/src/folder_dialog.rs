use std::path::PathBuf;

use meshelf_core::SaveDestination;

/// Open the native folder picker. The dialog is reached only from an explicit settings action.
pub fn choose_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_folder()
}

/// Resolve a persisted destination at activation time. Downloads is deliberately resolved here,
/// behind the platform boundary, rather than being copied into the controller's settings schema.
pub fn resolve_save_destination(destination: &SaveDestination) -> Result<PathBuf, String> {
    let path = match destination {
        SaveDestination::Downloads => {
            dirs::download_dir().ok_or_else(|| "the Downloads folder is unavailable".to_owned())?
        }
        SaveDestination::Custom { path } => path.clone(),
    };
    if !path.is_absolute() {
        return Err("save destination must be absolute".to_owned());
    }
    Ok(path)
}
