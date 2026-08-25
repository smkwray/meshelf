//! Portable destination-name authority shared by every file publication path.
//!
//! This module intentionally knows nothing about the host filesystem.  It rejects names that
//! would be ambiguous or unsafe on any supported host, including Windows device names and
//! trailing-dot/space spellings that Unix would otherwise accept.

use std::path::PathBuf;

use crate::MAX_OFFER_PORTABLE_COMPONENT_BYTES;

/// The strict, cross-platform destination policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DestinationPolicy;

impl DestinationPolicy {
    /// Validate one portable path component.
    pub fn validate_component(component: &str) -> Result<(), String> {
        validate_component(component)
    }

    /// Validate a slash-separated relative path.
    pub fn validate_relative_path(path: &str) -> Result<(), String> {
        validate_relative_path(path)
    }
}

/// Validate one portable path component for both Unix and Windows publication.
pub fn validate_component(component: &str) -> Result<(), String> {
    let contains_platform_forbidden_character = component.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    });
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_OFFER_PORTABLE_COMPONENT_BYTES
        || contains_platform_forbidden_character
    {
        return Err(format!("unsafe file name component: {component:?}"));
    }

    let device_stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let numbered_device_suffix = device_stem
        .strip_prefix("COM")
        .or_else(|| device_stem.strip_prefix("LPT"));
    let reserved = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || numbered_device_suffix.is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if reserved || component.ends_with(' ') || component.ends_with('.') {
        return Err(format!("platform-reserved file name: {component}"));
    }
    Ok(())
}

/// Validate a slash-separated relative path using the strict component policy.
pub fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 4096 {
        return Err("file path is empty or too long".to_owned());
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return Err(format!("unsafe file path: {path}"));
    }
    for component in path.split('/') {
        validate_component(component)?;
    }
    Ok(())
}

/// Convert a validated slash-separated path into a host path without interpreting it as an
/// absolute path.
#[must_use]
pub fn relative_path(value: &str) -> PathBuf {
    value.split('/').collect()
}
