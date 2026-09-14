//! Durable v2 offer, card, activation, clipboard-cache, and capture storage.
//!
//! The legacy receive ledger table remains defined solely so startup migration can remove its
//! rows. No operational v1 receive-store implementation remains reachable.

use meshelf_core::StoreError;
use redb::TableDefinition;

mod capture_v2;
mod v2;
pub use capture_v2::{
    CaptureGrantClaim, CapturePresentation, CaptureRequestInsert, CaptureRequestReconciliation,
    CaptureSourceClaim, CaptureSourceReconciliation, CaptureTombstonePrune, CaptureTransition,
    ClaimedCapturePull, MAX_CAPTURE_PHOTO_BYTES, MAX_CAPTURE_REQUEST_ROWS,
    MAX_CAPTURE_SOURCE_TOMBSTONES, MAX_LIVE_CAPTURE_REQUESTS,
};
pub use v2::{RedbV2Store, store_identity};

pub(crate) const RECEIVE_LEDGER: TableDefinition<&str, &[u8]> =
    TableDefinition::new("receive_ledger_v1");

pub(crate) fn map_redb_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::new(error.to_string())
}
