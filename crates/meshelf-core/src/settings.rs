use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The destination used by the later save activation. Step 4 stores this
/// value only; resolving Downloads and choosing a folder remain platform work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SaveDestination {
    #[default]
    Downloads,
    Custom {
        #[serde(deserialize_with = "deserialize_absolute_path")]
        path: PathBuf,
    },
}

fn deserialize_absolute_path<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = PathBuf::deserialize(deserializer)?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(serde::de::Error::custom(
            "custom save destination must be absolute",
        ))
    }
}

impl SaveDestination {
    pub fn custom(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if !path.is_absolute() {
            return Err("custom save destination must be absolute".to_owned());
        }
        Ok(Self::Custom { path })
    }

    #[must_use]
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            Self::Downloads => None,
            Self::Custom { path } => Some(path),
        }
    }
}

/// User configuration persisted in the installation state file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSettings {
    #[serde(default = "settings_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub save_destination: SaveDestination,
}

fn settings_schema_version() -> u32 {
    1
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            save_destination: SaveDestination::Downloads,
        }
    }
}
