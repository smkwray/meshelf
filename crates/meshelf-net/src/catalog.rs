//! Bounded origin catalog: metadata-only catch-up for ordinary shelf offers.

use std::sync::Arc;

use async_trait::async_trait;
use meshelf_core::{ActivationId, CardAvailability, DeviceId, OfferCardInput};
use meshelf_protocol::{
    CAP_SHELF_CATALOG_V1, CatalogEntry, CatalogRefusal, CatalogRefusalCode, CatalogRequest,
    CatalogSnapshot, V2_MAX_CATALOG_ENTRIES, V2_PROTOCOL_VERSION,
};
use meshelf_store::RedbV2Store;

use crate::NetError;

/// Serves [`CatalogRequest`] from an origin's retained ordinary sources.
#[async_trait]
pub trait CatalogOrigin: Send + Sync + 'static {
    async fn handle_catalog(
        &self,
        authenticated_requester: DeviceId,
        listener_device: DeviceId,
        request: CatalogRequest,
    ) -> Result<Result<CatalogSnapshot, CatalogRefusal>, NetError>;
}

/// Ordinary-source catalog backed by [`RedbV2Store`].
pub struct StoreCatalogOrigin {
    store: Arc<RedbV2Store>,
    origin_device: DeviceId,
}

impl StoreCatalogOrigin {
    #[must_use]
    pub fn new(store: Arc<RedbV2Store>, origin_device: DeviceId) -> Self {
        Self {
            store,
            origin_device,
        }
    }

    fn refuse(
        request_id: ActivationId,
        code: CatalogRefusalCode,
        detail: impl Into<String>,
    ) -> CatalogRefusal {
        CatalogRefusal {
            protocol_version: V2_PROTOCOL_VERSION,
            request_id,
            code,
            detail: Some(detail.into()),
        }
    }
}

#[async_trait]
impl CatalogOrigin for StoreCatalogOrigin {
    async fn handle_catalog(
        &self,
        authenticated_requester: DeviceId,
        listener_device: DeviceId,
        request: CatalogRequest,
    ) -> Result<Result<CatalogSnapshot, CatalogRefusal>, NetError> {
        if request.requester_device != authenticated_requester {
            return Ok(Err(Self::refuse(
                request.request_id,
                CatalogRefusalCode::RefusedInvalid,
                "requester device does not match authenticated client",
            )));
        }
        if request.origin_device != listener_device || request.origin_device != self.origin_device {
            return Ok(Err(Self::refuse(
                request.request_id,
                CatalogRefusalCode::RefusedInvalid,
                "origin device does not match listener",
            )));
        }
        let epoch = self
            .store
            .shelf_origin_epoch()
            .map_err(|error| NetError::OfferStorage(error.to_string()))?;
        let after = if request.origin_epoch == 0 || request.origin_epoch == epoch {
            request.after_ordinal
        } else {
            // Prior epoch frontier: send retained window from the start so the receiver replaces it.
            0
        };
        let records = self
            .store
            .list_ordinary_sources_after(after, V2_MAX_CATALOG_ENTRIES)
            .map_err(|error| NetError::OfferStorage(error.to_string()))?;
        let mut entries = Vec::with_capacity(records.len());
        for record in records {
            self.store
                .add_announced_recipient(record.offer_id, authenticated_requester)
                .map_err(|error| NetError::OfferStorage(error.to_string()))?;
            entries.push(CatalogEntry {
                offer_id: record.offer_id,
                origin_ordinal: record.creation_sequence,
                // Wall-clock was not stored on sources; receivers stamp cards locally if zero.
                created_at_unix_ms: 0,
                descriptor: record.descriptor,
            });
        }
        let highest = self
            .store
            .read_offer_sources()
            .map_err(|error| NetError::OfferStorage(error.to_string()))?
            .into_iter()
            .map(|record| record.creation_sequence)
            .max()
            .unwrap_or(0);
        Ok(Ok(CatalogSnapshot {
            protocol_version: V2_PROTOCOL_VERSION,
            request_id: request.request_id,
            origin_device: self.origin_device,
            requester_device: authenticated_requester,
            origin_epoch: epoch,
            highest_issued_ordinal: highest,
            entries,
        }))
    }
}

/// True when a hello advertises catalog support.
#[must_use]
pub fn hello_supports_catalog(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .any(|capability| capability == CAP_SHELF_CATALOG_V1)
}

/// Insert catalog entries into the local shelf and advance the origin frontier.
///
/// When `local_device` is set (phone ordinary index), card purge also removes owned sources so
/// own+received stay inside one ten-entry product shelf.
pub fn apply_catalog_snapshot(
    store: &RedbV2Store,
    snapshot: &CatalogSnapshot,
    local_device: Option<DeviceId>,
) -> Result<u32, NetError> {
    let mut inserted = 0_u32;
    for entry in &snapshot.entries {
        let result = store
            .insert_offer_card_on_ordinary_index(
                OfferCardInput::new(
                    snapshot.origin_device,
                    entry.offer_id,
                    entry.descriptor.clone(),
                    CardAvailability::Available,
                ),
                local_device,
            )
            .map_err(|error| NetError::OfferStorage(error.to_string()))?;
        if result.inserted {
            inserted = inserted.saturating_add(1);
        }
    }
    store
        .advance_catalog_frontier(
            snapshot.origin_device,
            snapshot.origin_epoch,
            snapshot.highest_issued_ordinal,
        )
        .map_err(|error| NetError::OfferStorage(error.to_string()))?;
    Ok(inserted)
}
