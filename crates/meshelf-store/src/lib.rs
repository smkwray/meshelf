//! Durable v2 offer, card, activation, and clipboard-cache storage.
//!
//! The legacy receive ledger table remains defined solely so startup migration can remove its
//! rows. No operational v1 receive-store implementation remains reachable.

use meshelf_core::StoreError;
use redb::TableDefinition;

mod v2;
pub use v2::{RedbV2Store, store_identity};

pub(crate) const RECEIVE_LEDGER: TableDefinition<&str, &[u8]> =
    TableDefinition::new("receive_ledger_v1");

pub(crate) fn map_redb_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::new(error.to_string())
}
