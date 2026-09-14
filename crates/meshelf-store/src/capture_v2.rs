//! Capture request (requester) and capture source (phone) tables.
//!
//! A capture never occupies the ten-entry offer shelf. `offer_sources_v2` and `offer_cards_v2`
//! purge their oldest row to admit an eleventh, so a transient photograph stored there could
//! evict a card the user was keeping. Captures therefore live in two bounded tables of their own,
//! and nothing in this module reads or writes a shelf table.
//!
//! Every transition is one redb write transaction that reads the row, checks its current phase,
//! and writes the next one. redb admits one write transaction at a time, so racing callers
//! serialize and only the first observes the phase it needs: exactly one announcement can claim a
//! pull grant, and a photograph is served at most once. A result other than an applied transition
//! or a won claim has changed nothing.
//!
//! Capture reconciliation is deliberately not part of `startup_cleanup`; the resident calls it
//! explicitly after activation-journal recovery.

use meshelf_core::{
    ActivationId, CaptureReceipt, CaptureRequestId, CaptureRequestPhase, CaptureRequestRecord,
    CaptureSourcePhase, CaptureSourceRecord, CaptureSourceTerminalCode, CaptureTerminalCode,
    CapturedPhoto, DeviceId, OfferDescriptor, OfferId, StoreError, validate_capture_detail,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::path::PathBuf;

use crate::{
    map_redb_error,
    v2::{RedbV2Store, decode_json, encode_json},
};

pub(crate) const CAPTURE_REQUESTS_V2: TableDefinition<&str, &[u8]> =
    TableDefinition::new("capture_requests_v2");
pub(crate) const CAPTURE_SOURCES_V2: TableDefinition<&str, &[u8]> =
    TableDefinition::new("capture_sources_v2");

/// Requester rows that may be awaiting presentation, armed, or claimed at once.
pub const MAX_LIVE_CAPTURE_REQUESTS: usize = 8;
/// All requester rows, live or finished. A finished row stays until its outcome is reported.
pub const MAX_CAPTURE_REQUEST_ROWS: usize = 32;
/// Finished phone rows (delivered, uncertain, or terminal) retained at any time.
pub const MAX_CAPTURE_SOURCE_TOMBSTONES: usize = 8;
/// The largest photograph a capture may carry; equal to `JpegSanitizer.MAX_JPEG_BYTES` in the
/// Android client, so the requester never refuses a photo the phone was allowed to produce.
pub const MAX_CAPTURE_PHOTO_BYTES: u64 = 64 * 1024 * 1024;

type Rows<'txn> = redb::Table<'txn, &'static str, &'static [u8]>;
type RowDefinition = TableDefinition<'static, &'static str, &'static [u8]>;

/// Outcome of recording a new capture request on the requester.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureRequestInsert {
    /// Written. `pruned_reported` counts rows whose outcome had already been reported and that
    /// were removed, oldest first, to stay within [`MAX_CAPTURE_REQUEST_ROWS`].
    Inserted {
        record: CaptureRequestRecord,
        pruned_reported: u32,
    },
    /// The same request is already stored; this is its current row. Nothing changed.
    Duplicate(CaptureRequestRecord),
    /// A different request already holds this id. Nothing changed.
    Conflict,
    /// Refused rather than grown: `live` requests are in flight, or `rows` rows hold outcomes
    /// that have not been reported yet. Nothing changed.
    AtCapacity { live: u32, rows: u32 },
}

/// Outcome of a phase transition on either table. Only `Applied` wrote anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureTransition<R> {
    /// The transition was committed; this is the new row.
    Applied(R),
    /// The row was already in the requested state, so this idempotent repeat changed nothing.
    Unchanged(R),
    /// The current phase forbids the transition; nothing changed. This is the current row.
    Refused(R),
    /// No row has this id.
    Unknown,
}

/// The authority for one automatic pull, returned only to the claim that won the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedCapturePull {
    pub request_id: CaptureRequestId,
    pub source: DeviceId,
    pub offer_id: OfferId,
    pub activation_id: ActivationId,
    pub descriptor: OfferDescriptor,
    pub exact_output_path: PathBuf,
}

/// Outcome of a correlated announcement trying to claim a pull grant. Only `Claimed` changed
/// anything; every refusal leaves the grant exactly as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureGrantClaim {
    Claimed(ClaimedCapturePull),
    /// An earlier announcement already claimed this grant, for this offer and activation.
    AlreadyClaimed {
        offer_id: OfferId,
        activation_id: ActivationId,
    },
    /// The grant is not armed: still awaiting presentation, or already finished.
    NotArmed,
    /// The announcement came from a device other than the grant's expected source.
    WrongSource,
    Expired,
    /// The descriptor is not exactly one valid, non-empty file.
    NotSingleFile,
    /// The file exceeds [`MAX_CAPTURE_PHOTO_BYTES`].
    TooLarge,
    Unknown,
}

/// What requester startup reconciliation did. Nothing is resumed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureRequestReconciliation {
    /// Unclaimed requests ended as `ResidentRestarted` before their expiry; the phone may still
    /// be presenting each one, so each deserves one best-effort cancel.
    pub cancel: Vec<CaptureRequestRecord>,
    /// Unclaimed requests ended as `ResidentRestarted` after their expiry had passed; the phone
    /// has already given up on them, so no cancel is owed.
    pub restarted_after_expiry: Vec<CaptureRequestRecord>,
    /// Claimed requests ended as `UncertainNoReplay`. Their pulls are never resumed: the caller
    /// may already have given up and moved on.
    pub uncertain: Vec<CaptureRequestRecord>,
    /// Rows whose outcome had already been reported, removed.
    pub pruned_reported: u32,
}

/// Outcome of the phone recording a capture request it received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturePresentation {
    /// Written. `pruned_tombstones` counts finished rows removed, oldest first, to make room.
    Presented {
        record: CaptureSourceRecord,
        pruned_tombstones: u32,
    },
    /// The same request is already stored; repeat the acknowledgement its phase implies.
    Duplicate(CaptureSourcePhase),
    /// Another request is live on this phone.
    Busy,
    /// A different request already holds this id.
    Conflict,
    /// Every tombstone slot holds an uncertain photo still awaiting its delete deadline.
    AtCapacity,
}

/// Outcome of a fetch trying to claim a captured photo for serving. Only `Claimed` changed
/// anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSourceClaim {
    /// Serve this photo now; it will never be served again.
    Claimed(Box<CaptureSourceRecord>),
    AlreadyClaimed,
    /// The photo exists but has not been announced.
    NotAnnounced,
    /// The fetch came from a device other than the one that requested the photo.
    WrongRequester,
    /// No row holds a photo with this offer id; delivered and uncertain rows keep none.
    Unknown,
}

/// What phone startup reconciliation did. Nothing that was already captured is re-presented.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureSourceReconciliation {
    /// The one live, unexpired request whose photo has not been taken; present it again under
    /// the same request id. Its row is unchanged.
    pub represent: Option<CaptureSourceRecord>,
    /// Rows ended by this reconciliation whose notification or photo must be withdrawn:
    /// expired live rows as `Expired`, and unexpired captured or announced rows as `Failed`.
    pub withdraw: Vec<CaptureSourceRecord>,
    /// Absolute photograph paths that must be deleted for the withdrawn rows that held one.
    pub deleted_photographs: Vec<(CaptureRequestId, std::path::PathBuf)>,
    /// Rows claimed when the phone stopped, now `UncertainNoReplay` until their photo's delete
    /// deadline. They are neither withdrawn nor delivered.
    pub uncertain: Vec<CaptureSourceRecord>,
}

/// What tombstone pruning did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureTombstonePrune {
    /// Uncertain rows past their deadline, now `Terminal ExpiredUnconfirmed`; delete each photo.
    /// None of them is ever recorded as delivered.
    pub expired_unconfirmed: Vec<CaptureSourceRecord>,
    /// Absolute photograph paths that must be deleted for the expired-unconfirmed rows above.
    /// Kept here because the durable row drops the path when it becomes terminal.
    pub deleted_photographs: Vec<(CaptureRequestId, std::path::PathBuf)>,
    /// Finished rows removed to stay within [`MAX_CAPTURE_SOURCE_TOMBSTONES`].
    pub removed: u32,
}

enum Step {
    Apply,
    Unchanged,
    Refuse,
}

impl RedbV2Store {
    /// Records a new request awaiting presentation. Idempotent by request id.
    pub fn insert_capture_request(
        &self,
        record: CaptureRequestRecord,
    ) -> Result<CaptureRequestInsert, StoreError> {
        record.validate()?;
        if record.phase != CaptureRequestPhase::AwaitingPresentation || record.terminal_reported {
            return Err(StoreError::new(
                "a new capture request must be awaiting presentation",
            ));
        }
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            if let Some(existing) = request_row(table, record.request_id)? {
                return Ok(if same_request(&existing, &record) {
                    CaptureRequestInsert::Duplicate(existing)
                } else {
                    CaptureRequestInsert::Conflict
                });
            }
            let rows = request_rows(table)?;
            let live = rows.iter().filter(|row| row.outcome().is_none()).count();
            let reported = rows.iter().filter(|row| row.terminal_reported).count();
            let excess = (rows.len() + 1).saturating_sub(MAX_CAPTURE_REQUEST_ROWS);
            if live >= MAX_LIVE_CAPTURE_REQUESTS || reported < excess {
                return Ok(CaptureRequestInsert::AtCapacity {
                    live: row_count(live)?,
                    rows: row_count(rows.len())?,
                });
            }
            let pruned_reported = remove_reported_requests(table, &rows, excess)?;
            put_request(table, &record)?;
            Ok(CaptureRequestInsert::Inserted {
                record,
                pruned_reported,
            })
        })
    }

    pub fn get_capture_request(
        &self,
        request_id: CaptureRequestId,
    ) -> Result<Option<CaptureRequestRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CAPTURE_REQUESTS_V2)
            .map_err(map_redb_error)?;
        request_row(&table, request_id)
    }

    /// Every requester row, newest first.
    pub fn read_capture_requests(&self) -> Result<Vec<CaptureRequestRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CAPTURE_REQUESTS_V2)
            .map_err(map_redb_error)?;
        let mut rows = request_rows(&table)?;
        rows.sort_by_key(|row| {
            std::cmp::Reverse((row.created_at_unix_ms, row.request_id.as_uuid()))
        });
        Ok(rows)
    }

    /// `AwaitingPresentation -> Armed` on a signed presentation acknowledgement, and only
    /// before the grant expires.
    pub fn arm_capture_grant(
        &self,
        request_id: CaptureRequestId,
        presented_at_unix_ms: u64,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        self.transition_request(request_id, |record| {
            Ok(
                if record.phase == CaptureRequestPhase::AwaitingPresentation
                    && presented_at_unix_ms < record.grant.expires_at_unix_ms
                {
                    record.phase = CaptureRequestPhase::Armed {
                        presented_at_unix_ms,
                    };
                    Step::Apply
                } else {
                    Step::Refuse
                },
            )
        })
    }

    /// Claims an armed grant for one correlated announcement. This is the only way an automatic
    /// pull starts, and one transaction decides it, so two racing announcements cannot both win.
    pub fn claim_capture_grant(
        &self,
        request_id: CaptureRequestId,
        source: DeviceId,
        offer_id: OfferId,
        activation_id: ActivationId,
        descriptor: OfferDescriptor,
        now_unix_ms: u64,
    ) -> Result<CaptureGrantClaim, StoreError> {
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            let Some(mut record) = request_row(table, request_id)? else {
                return Ok(CaptureGrantClaim::Unknown);
            };
            if source != record.grant.expected_source {
                return Ok(CaptureGrantClaim::WrongSource);
            }
            match &record.phase {
                CaptureRequestPhase::Armed { .. } => {}
                CaptureRequestPhase::Claimed {
                    offer_id,
                    activation_id,
                    ..
                } => {
                    return Ok(CaptureGrantClaim::AlreadyClaimed {
                        offer_id: *offer_id,
                        activation_id: *activation_id,
                    });
                }
                _ => return Ok(CaptureGrantClaim::NotArmed),
            }
            if now_unix_ms >= record.grant.expires_at_unix_ms {
                return Ok(CaptureGrantClaim::Expired);
            }
            let Some(total_bytes) = single_file_bytes(&descriptor) else {
                return Ok(CaptureGrantClaim::NotSingleFile);
            };
            if total_bytes > MAX_CAPTURE_PHOTO_BYTES {
                return Ok(CaptureGrantClaim::TooLarge);
            }
            record.phase = CaptureRequestPhase::Claimed {
                offer_id,
                activation_id,
                descriptor: descriptor.clone(),
            };
            put_request(table, &record)?;
            Ok(CaptureGrantClaim::Claimed(ClaimedCapturePull {
                request_id,
                source,
                offer_id,
                activation_id,
                descriptor,
                exact_output_path: record.grant.exact_output_path,
            }))
        })
    }

    /// `Claimed -> Completed` for the activation that claimed the grant, after the photo is
    /// published and synced. A receipt that disagrees with the claim is an error, not a
    /// completion: its byte count must equal the claimed file's and its path the grant's.
    pub fn complete_capture(
        &self,
        request_id: CaptureRequestId,
        activation_id: ActivationId,
        receipt: CaptureReceipt,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        self.transition_request(request_id, |record| {
            let claimed_bytes = match &record.phase {
                CaptureRequestPhase::Claimed {
                    activation_id: claimed,
                    descriptor,
                    ..
                } if *claimed == activation_id => single_file_bytes(descriptor),
                CaptureRequestPhase::Completed { receipt: stored } if *stored == receipt => {
                    return Ok(Step::Unchanged);
                }
                _ => return Ok(Step::Refuse),
            };
            if claimed_bytes != Some(receipt.bytes) {
                return Err(StoreError::new(
                    "capture receipt byte count differs from the claimed photo",
                ));
            }
            record.phase = CaptureRequestPhase::Completed { receipt };
            Ok(Step::Apply)
        })
    }

    /// Ends a live request. Terminal is sticky, a completed request is never re-terminated, and
    /// nothing leads back to `Armed`, so a failed claim is never re-armed. Repeating the same
    /// code is an idempotent no-op that keeps the first detail.
    pub fn terminate_capture(
        &self,
        request_id: CaptureRequestId,
        code: CaptureTerminalCode,
        detail: Option<String>,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        validate_capture_detail(&detail)?;
        self.transition_request(request_id, |record| {
            Ok(match &record.phase {
                CaptureRequestPhase::Terminal { code: existing, .. } if *existing == code => {
                    Step::Unchanged
                }
                CaptureRequestPhase::Completed { .. } | CaptureRequestPhase::Terminal { .. } => {
                    Step::Refuse
                }
                CaptureRequestPhase::AwaitingPresentation
                | CaptureRequestPhase::Armed { .. }
                | CaptureRequestPhase::Claimed { .. } => {
                    record.phase = CaptureRequestPhase::Terminal { code, detail };
                    Step::Apply
                }
            })
        })
    }

    /// Ends a request only while it is unclaimed, deciding and writing in one transaction. A
    /// status from the phone uses this: once a pull has claimed the grant, the pull owns the
    /// outcome, and a status that arrives after the claim changes nothing. Repeating the same code
    /// on a request it already ended is an idempotent no-op.
    pub fn terminate_capture_unless_claimed(
        &self,
        request_id: CaptureRequestId,
        code: CaptureTerminalCode,
        detail: Option<String>,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        validate_capture_detail(&detail)?;
        self.transition_request(request_id, |record| {
            Ok(match &record.phase {
                CaptureRequestPhase::Terminal { code: existing, .. } if *existing == code => {
                    Step::Unchanged
                }
                CaptureRequestPhase::AwaitingPresentation | CaptureRequestPhase::Armed { .. } => {
                    record.phase = CaptureRequestPhase::Terminal { code, detail };
                    Step::Apply
                }
                CaptureRequestPhase::Claimed { .. }
                | CaptureRequestPhase::Completed { .. }
                | CaptureRequestPhase::Terminal { .. } => Step::Refuse,
            })
        })
    }

    /// Ends every unclaimed request whose expiry has passed as `Expired`. A claimed request is
    /// left alone: its transfer has its own bounds. Returns the rows it ended.
    pub fn expire_due(&self, now_unix_ms: u64) -> Result<Vec<CaptureRequestRecord>, StoreError> {
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            let mut expired = Vec::new();
            for mut record in request_rows(table)? {
                if is_unclaimed(&record.phase) && now_unix_ms >= record.grant.expires_at_unix_ms {
                    record.phase = CaptureRequestPhase::Terminal {
                        code: CaptureTerminalCode::Expired,
                        detail: None,
                    };
                    put_request(table, &record)?;
                    expired.push(record);
                }
            }
            sort_requests_oldest_first(&mut expired);
            Ok(expired)
        })
    }

    /// Records that a finished request's outcome was reported. Refused while it is live.
    pub fn mark_capture_reported(
        &self,
        request_id: CaptureRequestId,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        self.transition_request(request_id, |record| {
            Ok(if record.outcome().is_none() {
                Step::Refuse
            } else if record.terminal_reported {
                Step::Unchanged
            } else {
                record.terminal_reported = true;
                Step::Apply
            })
        })
    }

    /// Removes every row whose outcome has been reported. Unreported outcomes are kept.
    pub fn prune_reported_capture_requests(&self) -> Result<u32, StoreError> {
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            let rows = request_rows(table)?;
            remove_reported_requests(table, &rows, usize::MAX)
        })
    }

    /// Requester startup: removes reported rows, ends every unclaimed request as
    /// `ResidentRestarted`, and ends every claimed request as `UncertainNoReplay`. No pull is
    /// ever resumed.
    pub fn reconcile_capture_requests_at_startup(
        &self,
        now_unix_ms: u64,
    ) -> Result<CaptureRequestReconciliation, StoreError> {
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            let mut rows = request_rows(table)?;
            let mut report = CaptureRequestReconciliation {
                pruned_reported: remove_reported_requests(table, &rows, usize::MAX)?,
                ..CaptureRequestReconciliation::default()
            };
            sort_requests_oldest_first(&mut rows);
            for mut record in rows.into_iter().filter(|row| !row.terminal_reported) {
                let code = match record.phase {
                    CaptureRequestPhase::AwaitingPresentation
                    | CaptureRequestPhase::Armed { .. } => CaptureTerminalCode::ResidentRestarted,
                    CaptureRequestPhase::Claimed { .. } => CaptureTerminalCode::UncertainNoReplay,
                    CaptureRequestPhase::Completed { .. }
                    | CaptureRequestPhase::Terminal { .. } => {
                        continue;
                    }
                };
                record.phase = CaptureRequestPhase::Terminal { code, detail: None };
                put_request(table, &record)?;
                if code == CaptureTerminalCode::UncertainNoReplay {
                    report.uncertain.push(record);
                } else if now_unix_ms < record.grant.expires_at_unix_ms {
                    report.cancel.push(record);
                } else {
                    report.restarted_after_expiry.push(record);
                }
            }
            Ok(report)
        })
    }

    /// Records a capture request the phone received, as `Presented`. At most one row is live.
    pub fn present_capture(
        &self,
        record: CaptureSourceRecord,
    ) -> Result<CapturePresentation, StoreError> {
        record.validate()?;
        if record.phase != CaptureSourcePhase::Presented {
            return Err(StoreError::new("a new capture source must be presented"));
        }
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            if let Some(existing) = source_row(table, record.request_id)? {
                return Ok(if same_source(&existing, &record) {
                    CapturePresentation::Duplicate(existing.phase)
                } else {
                    CapturePresentation::Conflict
                });
            }
            let rows = source_rows(table)?;
            if rows.iter().any(|row| is_live_source(&row.phase)) {
                return Ok(CapturePresentation::Busy);
            }
            // Leave one tombstone slot for this row, so it can finish without exceeding the bound.
            let pinned = rows.iter().filter(|row| is_pinned(&row.phase)).count();
            if pinned >= MAX_CAPTURE_SOURCE_TOMBSTONES {
                return Ok(CapturePresentation::AtCapacity);
            }
            let pruned_tombstones =
                evict_tombstones(table, &rows, MAX_CAPTURE_SOURCE_TOMBSTONES - 1)?;
            put_source(table, &record)?;
            Ok(CapturePresentation::Presented {
                record,
                pruned_tombstones,
            })
        })
    }

    /// `Presented -> Captured`, recording the photo before anything is announced.
    pub fn attach_captured(
        &self,
        request_id: CaptureRequestId,
        photo: CapturedPhoto,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        photo.validate()?;
        if single_file_bytes(&photo.descriptor).is_none_or(|bytes| bytes > MAX_CAPTURE_PHOTO_BYTES)
        {
            return Err(StoreError::new(
                "capture photo exceeds the maximum photo size",
            ));
        }
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            let rows = source_rows(table)?;
            let Some(current) = rows
                .iter()
                .find(|row| row.request_id == request_id)
                .cloned()
            else {
                return Ok(CaptureTransition::Unknown);
            };
            match &current.phase {
                CaptureSourcePhase::Presented => {}
                CaptureSourcePhase::Captured { photo: existing } if *existing == photo => {
                    return Ok(CaptureTransition::Unchanged(current));
                }
                _ => return Ok(CaptureTransition::Refused(current)),
            }
            if rows
                .iter()
                .filter_map(|row| photo_of(&row.phase))
                .any(|held| held.offer_id == photo.offer_id)
            {
                return Err(StoreError::new(
                    "capture photo offer id is already held by another capture",
                ));
            }
            let mut next = current;
            next.phase = CaptureSourcePhase::Captured { photo };
            put_source(table, &next)?;
            Ok(CaptureTransition::Applied(next))
        })
    }

    /// `Captured -> Announced`. Commit this before sending the announcement: the requester may
    /// fetch as soon as it arrives, and only an announced photo can be claimed.
    pub fn mark_capture_announced(
        &self,
        request_id: CaptureRequestId,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        self.transition_source(request_id, |record| {
            Ok(match &record.phase {
                CaptureSourcePhase::Captured { photo } => {
                    let photo = photo.clone();
                    record.phase = CaptureSourcePhase::Announced { photo };
                    Step::Apply
                }
                CaptureSourcePhase::Announced { .. } => Step::Unchanged,
                _ => Step::Refuse,
            })
        })
    }

    pub fn get_capture_source(
        &self,
        request_id: CaptureRequestId,
    ) -> Result<Option<CaptureSourceRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CAPTURE_SOURCES_V2)
            .map_err(map_redb_error)?;
        source_row(&table, request_id)
    }

    /// The row whose photo carries this offer id. Delivered and uncertain rows keep no photo, so
    /// they are never found here.
    pub fn get_capture_source_by_offer(
        &self,
        offer_id: OfferId,
    ) -> Result<Option<CaptureSourceRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CAPTURE_SOURCES_V2)
            .map_err(map_redb_error)?;
        Ok(source_rows(&table)?
            .into_iter()
            .find(|row| photo_of(&row.phase).is_some_and(|photo| photo.offer_id == offer_id)))
    }

    /// Every phone row, newest first.
    pub fn read_capture_sources(&self) -> Result<Vec<CaptureSourceRecord>, StoreError> {
        let read = self.database.begin_read().map_err(map_redb_error)?;
        let table = read
            .open_table(CAPTURE_SOURCES_V2)
            .map_err(map_redb_error)?;
        let mut rows = source_rows(&table)?;
        rows.sort_by_key(|row| {
            std::cmp::Reverse((row.created_at_unix_ms, row.request_id.as_uuid()))
        });
        Ok(rows)
    }

    /// `Announced -> Claimed` for the recorded requester, once. Run it before the first byte of
    /// the fetch header: this is what guarantees a photo is served at most once.
    pub fn claim_capture_source(
        &self,
        offer_id: OfferId,
        requester: DeviceId,
        activation_id: ActivationId,
    ) -> Result<CaptureSourceClaim, StoreError> {
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            let Some(mut record) = source_rows(table)?
                .into_iter()
                .find(|row| photo_of(&row.phase).is_some_and(|photo| photo.offer_id == offer_id))
            else {
                return Ok(CaptureSourceClaim::Unknown);
            };
            if record.requester != requester {
                return Ok(CaptureSourceClaim::WrongRequester);
            }
            let photo = match &record.phase {
                CaptureSourcePhase::Announced { photo } => photo.clone(),
                CaptureSourcePhase::Claimed { .. } => {
                    return Ok(CaptureSourceClaim::AlreadyClaimed);
                }
                _ => return Ok(CaptureSourceClaim::NotAnnounced),
            };
            record.phase = CaptureSourcePhase::Claimed {
                photo,
                activation_id,
            };
            put_source(table, &record)?;
            Ok(CaptureSourceClaim::Claimed(Box::new(record)))
        })
    }

    /// `Claimed -> Delivered`, a tombstone that keeps no path, after a completed receipt from the
    /// claiming activation reporting exactly one file of exactly the photo's byte count. Any
    /// other receipt is refused and the row stays claimed.
    pub fn mark_capture_delivered(
        &self,
        request_id: CaptureRequestId,
        activation_id: ActivationId,
        files_received: u32,
        bytes_received: u64,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        self.transition_source(request_id, |record| {
            let receipt_matches = match &record.phase {
                CaptureSourcePhase::Claimed {
                    photo,
                    activation_id: claimed,
                } => {
                    *claimed == activation_id
                        && files_received == 1
                        && single_file_bytes(&photo.descriptor) == Some(bytes_received)
                }
                CaptureSourcePhase::Delivered => return Ok(Step::Unchanged),
                _ => return Ok(Step::Refuse),
            };
            if !receipt_matches {
                return Ok(Step::Refuse);
            }
            record.phase = CaptureSourcePhase::Delivered;
            Ok(Step::Apply)
        })
    }

    /// `Claimed -> UncertainNoReplay` when the receipt was lost after serving. The photo is never
    /// served or announced again; its path is kept only so the phone can delete the bytes at
    /// `deadline_unix_ms` as expired-unconfirmed.
    pub fn mark_capture_uncertain(
        &self,
        request_id: CaptureRequestId,
        deadline_unix_ms: u64,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        self.transition_source(request_id, |record| {
            Ok(
                match std::mem::replace(
                    &mut record.phase,
                    CaptureSourcePhase::Terminal {
                        code: CaptureSourceTerminalCode::Failed,
                    },
                ) {
                    CaptureSourcePhase::Claimed { photo, .. } => {
                        record.phase = CaptureSourcePhase::UncertainNoReplay {
                            deadline_unix_ms,
                            path: photo.path,
                        };
                        Step::Apply
                    }
                    CaptureSourcePhase::UncertainNoReplay {
                        deadline_unix_ms: existing_deadline,
                        path,
                    } => {
                        record.phase = CaptureSourcePhase::UncertainNoReplay {
                            deadline_unix_ms: existing_deadline,
                            path,
                        };
                        Step::Unchanged
                    }
                    other => {
                        record.phase = other;
                        Step::Refuse
                    }
                },
            )
        })
    }

    /// Ends a request before its photo was claimed. Once claimed, a row ends as delivered, as
    /// uncertain, or as `Failed` when its fetch failed before `FetchComplete`: the requester
    /// publishes only after receiving every byte, so such a fetch provably did not deliver and the
    /// photo may be deleted at once. `ExpiredUnconfirmed` is reserved for uncertain rows past
    /// their deadline.
    pub fn terminate_capture_source(
        &self,
        request_id: CaptureRequestId,
        code: CaptureSourceTerminalCode,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        if code == CaptureSourceTerminalCode::ExpiredUnconfirmed {
            return Err(StoreError::new(
                "expired_unconfirmed is recorded only by tombstone pruning",
            ));
        }
        self.transition_source(request_id, |record| {
            Ok(match record.phase {
                CaptureSourcePhase::Terminal { code: existing } if existing == code => {
                    Step::Unchanged
                }
                CaptureSourcePhase::Presented
                | CaptureSourcePhase::Captured { .. }
                | CaptureSourcePhase::Announced { .. } => {
                    record.phase = CaptureSourcePhase::Terminal { code };
                    Step::Apply
                }
                CaptureSourcePhase::Claimed { .. } if code == CaptureSourceTerminalCode::Failed => {
                    record.phase = CaptureSourcePhase::Terminal { code };
                    Step::Apply
                }
                _ => Step::Refuse,
            })
        })
    }

    /// Phone startup. Re-presents the one live unexpired request whose photo has not been taken;
    /// never re-presents or re-announces one already captured; ends a claimed row as uncertain;
    /// ends an expired live row as `Expired`. Call [`Self::prune_capture_tombstones`] after it.
    pub fn reconcile_capture_sources_at_startup(
        &self,
        now_unix_ms: u64,
    ) -> Result<CaptureSourceReconciliation, StoreError> {
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            let live: Vec<CaptureSourceRecord> = source_rows(table)?
                .into_iter()
                .filter(|row| is_live_source(&row.phase))
                .collect();
            if live.len() > 1 {
                return Err(StoreError::new(format!(
                    "capture source table holds {} live rows; at most one is allowed",
                    live.len()
                )));
            }
            let mut report = CaptureSourceReconciliation::default();
            for mut record in live {
                let expired = now_unix_ms >= record.expires_at_unix_ms;
                let next = match &record.phase {
                    CaptureSourcePhase::Presented if !expired => {
                        report.represent = Some(record);
                        continue;
                    }
                    CaptureSourcePhase::Claimed { photo, .. } => {
                        CaptureSourcePhase::UncertainNoReplay {
                            deadline_unix_ms: photo.delete_deadline_unix_ms,
                            path: photo.path.clone(),
                        }
                    }
                    CaptureSourcePhase::Captured { photo }
                    | CaptureSourcePhase::Announced { photo } => {
                        report
                            .deleted_photographs
                            .push((record.request_id, photo.path.clone()));
                        if expired {
                            CaptureSourcePhase::Terminal {
                                code: CaptureSourceTerminalCode::Expired,
                            }
                        } else {
                            CaptureSourcePhase::Terminal {
                                code: CaptureSourceTerminalCode::Failed,
                            }
                        }
                    }
                    _ if expired => CaptureSourcePhase::Terminal {
                        code: CaptureSourceTerminalCode::Expired,
                    },
                    _ => CaptureSourcePhase::Terminal {
                        code: CaptureSourceTerminalCode::Failed,
                    },
                };
                record.phase = next;
                put_source(table, &record)?;
                if matches!(record.phase, CaptureSourcePhase::UncertainNoReplay { .. }) {
                    report.uncertain.push(record);
                } else {
                    report.withdraw.push(record);
                }
            }
            Ok(report)
        })
    }

    /// Ends every uncertain row past its deadline as `Terminal ExpiredUnconfirmed`, then removes
    /// the oldest delivered or terminal rows beyond [`MAX_CAPTURE_SOURCE_TOMBSTONES`]. An
    /// uncertain row is never removed before its deadline.
    pub fn prune_capture_tombstones(
        &self,
        now_unix_ms: u64,
    ) -> Result<CaptureTombstonePrune, StoreError> {
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            let mut report = CaptureTombstonePrune::default();
            let mut rows = source_rows(table)?;
            for record in &mut rows {
                if let CaptureSourcePhase::UncertainNoReplay {
                    deadline_unix_ms,
                    path,
                } = &record.phase
                    && now_unix_ms >= *deadline_unix_ms
                {
                    let path = path.clone();
                    let request_id = record.request_id;
                    record.phase = CaptureSourcePhase::Terminal {
                        code: CaptureSourceTerminalCode::ExpiredUnconfirmed,
                    };
                    put_source(table, record)?;
                    report.expired_unconfirmed.push(record.clone());
                    report.deleted_photographs.push((request_id, path));
                }
            }
            sort_sources_oldest_first(&mut report.expired_unconfirmed);
            report.removed = evict_tombstones(table, &rows, MAX_CAPTURE_SOURCE_TOMBSTONES)?;
            Ok(report)
        })
    }

    fn capture_write<R>(
        &self,
        definition: RowDefinition,
        operation: impl FnOnce(&mut Rows<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let write = self.database.begin_write().map_err(map_redb_error)?;
        let result = {
            let mut table = write.open_table(definition).map_err(map_redb_error)?;
            operation(&mut table)?
        };
        write.commit().map_err(map_redb_error)?;
        Ok(result)
    }

    fn transition_request(
        &self,
        request_id: CaptureRequestId,
        decide: impl FnOnce(&mut CaptureRequestRecord) -> Result<Step, StoreError>,
    ) -> Result<CaptureTransition<CaptureRequestRecord>, StoreError> {
        self.capture_write(CAPTURE_REQUESTS_V2, |table| {
            let Some(current) = request_row(table, request_id)? else {
                return Ok(CaptureTransition::Unknown);
            };
            let mut next = current.clone();
            Ok(match decide(&mut next)? {
                Step::Apply => {
                    put_request(table, &next)?;
                    CaptureTransition::Applied(next)
                }
                Step::Unchanged => CaptureTransition::Unchanged(current),
                Step::Refuse => CaptureTransition::Refused(current),
            })
        })
    }

    fn transition_source(
        &self,
        request_id: CaptureRequestId,
        decide: impl FnOnce(&mut CaptureSourceRecord) -> Result<Step, StoreError>,
    ) -> Result<CaptureTransition<CaptureSourceRecord>, StoreError> {
        self.capture_write(CAPTURE_SOURCES_V2, |table| {
            let Some(current) = source_row(table, request_id)? else {
                return Ok(CaptureTransition::Unknown);
            };
            let mut next = current.clone();
            Ok(match decide(&mut next)? {
                Step::Apply => {
                    put_source(table, &next)?;
                    CaptureTransition::Applied(next)
                }
                Step::Unchanged => CaptureTransition::Unchanged(current),
                Step::Refuse => CaptureTransition::Refused(current),
            })
        })
    }
}

fn row_count(value: usize) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::new("too many capture rows"))
}

/// The byte count of a descriptor that is exactly one valid, non-empty file.
fn single_file_bytes(descriptor: &OfferDescriptor) -> Option<u64> {
    match descriptor {
        OfferDescriptor::File { total_bytes, .. }
            if *total_bytes > 0 && descriptor.validate().is_ok() =>
        {
            Some(*total_bytes)
        }
        _ => None,
    }
}

fn is_unclaimed(phase: &CaptureRequestPhase) -> bool {
    matches!(
        phase,
        CaptureRequestPhase::AwaitingPresentation | CaptureRequestPhase::Armed { .. }
    )
}

/// The request as the caller asked for it: every field except its progress.
fn same_request(stored: &CaptureRequestRecord, offered: &CaptureRequestRecord) -> bool {
    let CaptureRequestRecord {
        request_id,
        peer,
        peer_label,
        purpose,
        lens,
        created_at_unix_ms,
        grant,
        phase: _,
        terminal_reported: _,
    } = stored;
    *request_id == offered.request_id
        && *peer == offered.peer
        && *peer_label == offered.peer_label
        && *purpose == offered.purpose
        && *lens == offered.lens
        && *created_at_unix_ms == offered.created_at_unix_ms
        && *grant == offered.grant
}

fn request_rows(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Vec<CaptureRequestRecord>, StoreError> {
    let mut rows: Vec<CaptureRequestRecord> = Vec::new();
    for entry in table.iter().map_err(map_redb_error)? {
        let (_, value) = entry.map_err(map_redb_error)?;
        rows.push(decode_json!(value.value())?);
    }
    Ok(rows)
}

fn request_row(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    request_id: CaptureRequestId,
) -> Result<Option<CaptureRequestRecord>, StoreError> {
    let key = request_id.to_string();
    table
        .get(key.as_str())
        .map_err(map_redb_error)?
        .map(|guard| decode_json!(guard.value()))
        .transpose()
}

fn put_request(table: &mut Rows<'_>, record: &CaptureRequestRecord) -> Result<(), StoreError> {
    record.validate()?;
    let key = record.request_id.to_string();
    let encoded = encode_json!(record)?;
    table
        .insert(key.as_str(), encoded.as_slice())
        .map_err(map_redb_error)?;
    Ok(())
}

fn sort_requests_oldest_first(rows: &mut [CaptureRequestRecord]) {
    rows.sort_by_key(|row| (row.created_at_unix_ms, row.request_id.as_uuid()));
}

/// Removes up to `limit` reported rows, oldest first.
fn remove_reported_requests(
    table: &mut Rows<'_>,
    rows: &[CaptureRequestRecord],
    limit: usize,
) -> Result<u32, StoreError> {
    let mut reported: Vec<CaptureRequestRecord> = rows
        .iter()
        .filter(|row| row.terminal_reported)
        .cloned()
        .collect();
    sort_requests_oldest_first(&mut reported);
    let mut removed = 0;
    for row in reported.iter().take(limit) {
        let key = row.request_id.to_string();
        table.remove(key.as_str()).map_err(map_redb_error)?;
        removed += 1;
    }
    row_count(removed)
}

fn is_live_source(phase: &CaptureSourcePhase) -> bool {
    matches!(
        phase,
        CaptureSourcePhase::Presented
            | CaptureSourcePhase::Captured { .. }
            | CaptureSourcePhase::Announced { .. }
            | CaptureSourcePhase::Claimed { .. }
    )
}

/// An uncertain row still owes a deletion at its deadline, so it is never evicted early.
fn is_pinned(phase: &CaptureSourcePhase) -> bool {
    matches!(phase, CaptureSourcePhase::UncertainNoReplay { .. })
}

fn photo_of(phase: &CaptureSourcePhase) -> Option<&CapturedPhoto> {
    match phase {
        CaptureSourcePhase::Captured { photo }
        | CaptureSourcePhase::Announced { photo }
        | CaptureSourcePhase::Claimed { photo, .. } => Some(photo),
        CaptureSourcePhase::Presented
        | CaptureSourcePhase::Delivered
        | CaptureSourcePhase::UncertainNoReplay { .. }
        | CaptureSourcePhase::Terminal { .. } => None,
    }
}

/// The request as the requester sent it: every field except its progress.
fn same_source(stored: &CaptureSourceRecord, offered: &CaptureSourceRecord) -> bool {
    let CaptureSourceRecord {
        request_id,
        requester,
        requester_label,
        purpose,
        lens,
        created_at_unix_ms,
        expires_at_unix_ms,
        phase: _,
    } = stored;
    *request_id == offered.request_id
        && *requester == offered.requester
        && *requester_label == offered.requester_label
        && *purpose == offered.purpose
        && *lens == offered.lens
        && *created_at_unix_ms == offered.created_at_unix_ms
        && *expires_at_unix_ms == offered.expires_at_unix_ms
}

fn source_rows(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Vec<CaptureSourceRecord>, StoreError> {
    let mut rows: Vec<CaptureSourceRecord> = Vec::new();
    for entry in table.iter().map_err(map_redb_error)? {
        let (_, value) = entry.map_err(map_redb_error)?;
        rows.push(decode_json!(value.value())?);
    }
    Ok(rows)
}

fn source_row(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    request_id: CaptureRequestId,
) -> Result<Option<CaptureSourceRecord>, StoreError> {
    let key = request_id.to_string();
    table
        .get(key.as_str())
        .map_err(map_redb_error)?
        .map(|guard| decode_json!(guard.value()))
        .transpose()
}

fn put_source(table: &mut Rows<'_>, record: &CaptureSourceRecord) -> Result<(), StoreError> {
    record.validate()?;
    let key = record.request_id.to_string();
    let encoded = encode_json!(record)?;
    table
        .insert(key.as_str(), encoded.as_slice())
        .map_err(map_redb_error)?;
    Ok(())
}

fn sort_sources_oldest_first(rows: &mut [CaptureSourceRecord]) {
    rows.sort_by_key(|row| (row.created_at_unix_ms, row.request_id.as_uuid()));
}

/// Removes the oldest delivered or terminal rows until at most `keep` finished rows remain, or
/// until only uncertain rows are left above it.
fn evict_tombstones(
    table: &mut Rows<'_>,
    rows: &[CaptureSourceRecord],
    keep: usize,
) -> Result<u32, StoreError> {
    let finished = rows
        .iter()
        .filter(|row| !is_live_source(&row.phase))
        .count();
    let mut evictable: Vec<CaptureSourceRecord> = rows
        .iter()
        .filter(|row| !is_live_source(&row.phase) && !is_pinned(&row.phase))
        .cloned()
        .collect();
    sort_sources_oldest_first(&mut evictable);
    let mut removed = 0;
    for row in evictable.iter().take(finished.saturating_sub(keep)) {
        let key = row.request_id.to_string();
        table.remove(key.as_str()).map_err(map_redb_error)?;
        removed += 1;
    }
    row_count(removed)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fmt::Debug,
        sync::{
            Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };

    use meshelf_core::{
        CaptureKind, CaptureLens, CaptureOutcome, CapturePullGrant, CardAvailability,
        MAX_CAPTURE_LIFETIME_MS, OfferCardInput, OfferSource, OfferSourceInput,
        V2_MAX_LIVE_ENTRIES,
    };
    use tempfile::{TempDir, tempdir};

    use super::*;

    const CREATED: u64 = 1_000_000;
    const EXPIRES: u64 = CREATED + MAX_CAPTURE_LIFETIME_MS;
    const PRESENTED: u64 = CREATED + 10;
    const NOW: u64 = CREATED + 20;
    const PHOTO_BYTES: u64 = 48_213;
    const DELETE_DEADLINE: u64 = CREATED + 600_000;

    /// Distinct, increasing creation times, so "oldest first" is well defined within a test.
    fn next_created() -> u64 {
        static TICK: AtomicU64 = AtomicU64::new(1);
        CREATED + TICK.fetch_add(1, Ordering::Relaxed)
    }

    fn open_store() -> (TempDir, RedbV2Store) {
        let directory = tempdir().expect("temporary directory");
        let store = RedbV2Store::open(directory.path().join("meshelf.redb")).expect("open store");
        (directory, store)
    }

    fn photo_descriptor() -> OfferDescriptor {
        OfferDescriptor::File {
            root_name: "capture.jpg".to_owned(),
            total_bytes: PHOTO_BYTES,
            content_class: meshelf_core::FileContentClass::File,
        }
    }

    fn file_of(total_bytes: u64) -> OfferDescriptor {
        OfferDescriptor::File {
            root_name: "capture.jpg".to_owned(),
            total_bytes,
            content_class: meshelf_core::FileContentClass::File,
        }
    }

    fn request(peer: DeviceId) -> CaptureRequestRecord {
        let request_id = CaptureRequestId::new();
        CaptureRequestRecord {
            request_id,
            peer,
            peer_label: "amber".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: Some(CaptureLens::Rear),
            created_at_unix_ms: next_created(),
            grant: CapturePullGrant {
                expected_source: peer,
                kind: CaptureKind::Photo,
                exact_output_path: std::env::temp_dir().join(format!("{request_id}.jpg")),
                expires_at_unix_ms: EXPIRES,
            },
            phase: CaptureRequestPhase::AwaitingPresentation,
            terminal_reported: false,
        }
    }

    fn receipt(record: &CaptureRequestRecord) -> CaptureReceipt {
        CaptureReceipt {
            output_path: record.grant.exact_output_path.clone(),
            sha256: [0xab; 32],
            bytes: PHOTO_BYTES,
            width: 4032,
            height: 3024,
        }
    }

    fn inserted(store: &RedbV2Store, record: CaptureRequestRecord) -> CaptureRequestRecord {
        match store
            .insert_capture_request(record)
            .expect("insert request")
        {
            CaptureRequestInsert::Inserted { record, .. } => record,
            other => panic!("expected an insert, got {other:?}"),
        }
    }

    fn applied<R: Debug>(transition: CaptureTransition<R>) -> R {
        match transition {
            CaptureTransition::Applied(record) => record,
            other => panic!("expected an applied transition, got {other:?}"),
        }
    }

    fn label<R>(transition: &CaptureTransition<R>) -> &'static str {
        match transition {
            CaptureTransition::Applied(_) => "applied",
            CaptureTransition::Unchanged(_) => "unchanged",
            CaptureTransition::Refused(_) => "refused",
            CaptureTransition::Unknown => "unknown",
        }
    }

    fn grant_label(claim: &CaptureGrantClaim) -> &'static str {
        match claim {
            CaptureGrantClaim::Claimed(_) => "claimed",
            CaptureGrantClaim::AlreadyClaimed { .. } => "already_claimed",
            CaptureGrantClaim::NotArmed => "not_armed",
            CaptureGrantClaim::WrongSource => "wrong_source",
            CaptureGrantClaim::Expired => "expired",
            CaptureGrantClaim::NotSingleFile => "not_single_file",
            CaptureGrantClaim::TooLarge => "too_large",
            CaptureGrantClaim::Unknown => "unknown",
        }
    }

    fn source_claim_label(claim: &CaptureSourceClaim) -> &'static str {
        match claim {
            CaptureSourceClaim::Claimed(_) => "claimed",
            CaptureSourceClaim::AlreadyClaimed => "already_claimed",
            CaptureSourceClaim::NotAnnounced => "not_announced",
            CaptureSourceClaim::WrongRequester => "wrong_requester",
            CaptureSourceClaim::Unknown => "unknown",
        }
    }

    fn request_phase_name(phase: &CaptureRequestPhase) -> &'static str {
        match phase {
            CaptureRequestPhase::AwaitingPresentation => "awaiting_presentation",
            CaptureRequestPhase::Armed { .. } => "armed",
            CaptureRequestPhase::Claimed { .. } => "claimed",
            CaptureRequestPhase::Completed { .. } => "completed",
            CaptureRequestPhase::Terminal { .. } => "terminal",
        }
    }

    fn source_phase_name(phase: &CaptureSourcePhase) -> &'static str {
        match phase {
            CaptureSourcePhase::Presented => "presented",
            CaptureSourcePhase::Captured { .. } => "captured",
            CaptureSourcePhase::Announced { .. } => "announced",
            CaptureSourcePhase::Claimed { .. } => "claimed",
            CaptureSourcePhase::Delivered => "delivered",
            CaptureSourcePhase::UncertainNoReplay { .. } => "uncertain_no_replay",
            CaptureSourcePhase::Terminal { .. } => "terminal",
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum At {
        Awaiting,
        Armed,
        Claimed,
        Completed,
        Terminal,
    }

    /// Drives a fresh request through the production transitions to `at`, returning it with
    /// the activation that claimed (or would claim) it.
    fn request_at(store: &RedbV2Store, at: At) -> (CaptureRequestRecord, ActivationId) {
        let record = inserted(store, request(DeviceId::new()));
        let id = record.request_id;
        let activation = ActivationId::new();
        if at == At::Awaiting {
            return (record, activation);
        }
        if at == At::Terminal {
            let ended = store
                .terminate_capture(
                    id,
                    CaptureTerminalCode::Declined,
                    Some("user-declined".into()),
                )
                .expect("terminate");
            return (applied(ended), activation);
        }
        let record = applied(store.arm_capture_grant(id, PRESENTED).expect("arm"));
        if at == At::Armed {
            return (record, activation);
        }
        let claim = store
            .claim_capture_grant(
                id,
                record.peer,
                OfferId::new(),
                activation,
                photo_descriptor(),
                NOW,
            )
            .expect("claim");
        assert!(matches!(claim, CaptureGrantClaim::Claimed(_)), "{claim:?}");
        let record = store.get_capture_request(id).expect("read").expect("row");
        if at == At::Claimed {
            return (record, activation);
        }
        let completed = store
            .complete_capture(id, activation, receipt(&record))
            .expect("complete");
        (applied(completed), activation)
    }

    fn source_request(requester: DeviceId) -> CaptureSourceRecord {
        CaptureSourceRecord {
            request_id: CaptureRequestId::new(),
            requester,
            requester_label: "CEDAR".to_owned(),
            purpose: "Photograph the router label".to_owned(),
            lens: None,
            created_at_unix_ms: next_created(),
            expires_at_unix_ms: EXPIRES,
            phase: CaptureSourcePhase::Presented,
        }
    }

    fn photo() -> CapturedPhoto {
        CapturedPhoto {
            offer_id: OfferId::new(),
            descriptor: photo_descriptor(),
            path: std::env::temp_dir()
                .join("agent-captures")
                .join("capture.jpg"),
            sha256: [0x5c; 32],
            width: 4032,
            height: 3024,
            delete_deadline_unix_ms: DELETE_DEADLINE,
        }
    }

    fn presented(store: &RedbV2Store, record: CaptureSourceRecord) -> CaptureSourceRecord {
        match store.present_capture(record).expect("present") {
            CapturePresentation::Presented { record, .. } => record,
            other => panic!("expected a presentation, got {other:?}"),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SourceAt {
        Presented,
        Captured,
        Announced,
        Claimed,
        Delivered,
        Uncertain,
        Terminal,
    }

    /// Drives a fresh phone row through the production transitions to `at`, returning it with
    /// its photo (attached from `Captured` on) and the activation that claimed (or would claim)
    /// it.
    fn source_at(
        store: &RedbV2Store,
        at: SourceAt,
    ) -> (CaptureSourceRecord, CapturedPhoto, ActivationId) {
        let record = presented(store, source_request(DeviceId::new()));
        let id = record.request_id;
        let photo = photo();
        let activation = ActivationId::new();
        let record = match at {
            SourceAt::Presented => record,
            SourceAt::Terminal => applied(
                store
                    .terminate_capture_source(id, CaptureSourceTerminalCode::Declined)
                    .expect("terminate"),
            ),
            _ => {
                let mut record = applied(store.attach_captured(id, photo.clone()).expect("attach"));
                if at != SourceAt::Captured {
                    record = applied(store.mark_capture_announced(id).expect("announce"));
                }
                if !matches!(at, SourceAt::Captured | SourceAt::Announced) {
                    let claim = store
                        .claim_capture_source(photo.offer_id, record.requester, activation)
                        .expect("claim");
                    assert!(matches!(claim, CaptureSourceClaim::Claimed(_)), "{claim:?}");
                    record = match at {
                        SourceAt::Delivered => applied(
                            store
                                .mark_capture_delivered(id, activation, 1, PHOTO_BYTES)
                                .expect("deliver"),
                        ),
                        SourceAt::Uncertain => applied(
                            store
                                .mark_capture_uncertain(id, DELETE_DEADLINE)
                                .expect("uncertain"),
                        ),
                        _ => store.get_capture_source(id).expect("read").expect("row"),
                    };
                }
                record
            }
        };
        (record, photo, activation)
    }

    type RequestOp = fn(&RedbV2Store, &CaptureRequestRecord, ActivationId) -> &'static str;

    #[test]
    fn requester_transition_legality_matrix() {
        const PHASES: [At; 5] = [
            At::Awaiting,
            At::Armed,
            At::Claimed,
            At::Completed,
            At::Terminal,
        ];
        // Columns follow PHASES. The last field is the phase an applied transition must reach;
        // `None` means the phase stays and only the reported flag is set.
        let matrix: [(&str, RequestOp, [&str; 5], Option<&str>); 6] = [
            (
                "arm",
                |store, record, _| {
                    label(
                        &store
                            .arm_capture_grant(record.request_id, PRESENTED)
                            .expect("arm"),
                    )
                },
                ["applied", "refused", "refused", "refused", "refused"],
                Some("armed"),
            ),
            (
                "claim",
                |store, record, _| {
                    grant_label(
                        &store
                            .claim_capture_grant(
                                record.request_id,
                                record.peer,
                                OfferId::new(),
                                ActivationId::new(),
                                photo_descriptor(),
                                NOW,
                            )
                            .expect("claim"),
                    )
                },
                [
                    "not_armed",
                    "claimed",
                    "already_claimed",
                    "not_armed",
                    "not_armed",
                ],
                Some("claimed"),
            ),
            (
                "complete",
                |store, record, activation| {
                    label(
                        &store
                            .complete_capture(record.request_id, activation, receipt(record))
                            .expect("complete"),
                    )
                },
                ["refused", "refused", "applied", "unchanged", "refused"],
                Some("completed"),
            ),
            (
                "terminate",
                |store, record, _| {
                    label(
                        &store
                            .terminate_capture(
                                record.request_id,
                                CaptureTerminalCode::Cancelled,
                                None,
                            )
                            .expect("terminate"),
                    )
                },
                ["applied", "applied", "applied", "refused", "refused"],
                Some("terminal"),
            ),
            (
                "report",
                |store, record, _| {
                    label(
                        &store
                            .mark_capture_reported(record.request_id)
                            .expect("report"),
                    )
                },
                ["refused", "refused", "refused", "applied", "applied"],
                None,
            ),
            (
                "expire",
                |store, record, _| {
                    let expired = store.expire_due(EXPIRES).expect("expire");
                    if expired
                        .iter()
                        .any(|row| row.request_id == record.request_id)
                    {
                        "applied"
                    } else {
                        "untouched"
                    }
                },
                ["applied", "applied", "untouched", "untouched", "untouched"],
                Some("terminal"),
            ),
        ];
        for (operation, run, expected, applied_phase) in matrix {
            let (_directory, store) = open_store();
            for (at, want) in PHASES.into_iter().zip(expected) {
                let (record, activation) = request_at(&store, at);
                let before = store
                    .get_capture_request(record.request_id)
                    .expect("read")
                    .expect("row");
                let seen = run(&store, &record, activation);
                assert_eq!(seen, want, "{operation} from {at:?}");
                let after = store
                    .get_capture_request(record.request_id)
                    .expect("read")
                    .expect("row");
                if matches!(seen, "applied" | "claimed") {
                    match applied_phase {
                        Some(name) => assert_eq!(
                            request_phase_name(&after.phase),
                            name,
                            "{operation} from {at:?}"
                        ),
                        None => {
                            assert!(after.terminal_reported);
                            assert_eq!(after.phase, before.phase);
                        }
                    }
                } else {
                    assert_eq!(after, before, "{operation} from {at:?} must change nothing");
                }
            }
        }
    }

    #[test]
    fn two_announcements_racing_for_one_grant_start_exactly_one_pull() {
        let (_directory, store) = open_store();
        for round in 0..32 {
            let (record, _) = request_at(&store, At::Armed);
            let id = record.request_id;
            let barrier = Barrier::new(2);
            let claims: Vec<CaptureGrantClaim> = thread::scope(|scope| {
                let racers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            store
                                .claim_capture_grant(
                                    id,
                                    record.peer,
                                    OfferId::new(),
                                    ActivationId::new(),
                                    photo_descriptor(),
                                    NOW,
                                )
                                .expect("claim")
                        })
                    })
                    .collect();
                racers
                    .into_iter()
                    .map(|racer| racer.join().expect("racer"))
                    .collect()
            });
            let winners: Vec<&ClaimedCapturePull> = claims
                .iter()
                .filter_map(|claim| match claim {
                    CaptureGrantClaim::Claimed(pull) => Some(pull),
                    _ => None,
                })
                .collect();
            assert_eq!(winners.len(), 1, "round {round}: {claims:?}");
            let winner = winners[0];
            let loser = CaptureGrantClaim::AlreadyClaimed {
                offer_id: winner.offer_id,
                activation_id: winner.activation_id,
            };
            assert!(claims.contains(&loser), "round {round}: {claims:?}");
            match store
                .get_capture_request(id)
                .expect("read")
                .expect("row")
                .phase
            {
                CaptureRequestPhase::Claimed {
                    offer_id,
                    activation_id,
                    ..
                } => assert_eq!(
                    (offer_id, activation_id),
                    (winner.offer_id, winner.activation_id)
                ),
                other => panic!("round {round}: {other:?}"),
            }
            applied(
                store
                    .terminate_capture(id, CaptureTerminalCode::TransferFailed, None)
                    .expect("terminate"),
            );
            applied(store.mark_capture_reported(id).expect("report"));
            store.prune_reported_capture_requests().expect("prune");
        }
    }

    #[test]
    fn a_claim_after_expiry_from_the_wrong_source_or_for_anything_but_one_nonempty_file_is_refused()
    {
        let (_directory, store) = open_store();
        let (armed, _) = request_at(&store, At::Armed);
        let id = armed.request_id;
        let peer = armed.peer;
        let claim = |source: DeviceId, descriptor: OfferDescriptor, now: u64| {
            store
                .claim_capture_grant(
                    id,
                    source,
                    OfferId::new(),
                    ActivationId::new(),
                    descriptor,
                    now,
                )
                .expect("claim")
        };
        let folder = OfferDescriptor::Folder {
            root_name: "photos".to_owned(),
            total_bytes: 10,
            entry_count: 1,
            file_count: 1,
            directory_count: 0,
        };
        let escaping = OfferDescriptor::File {
            root_name: "../escape.jpg".to_owned(),
            total_bytes: 10,
            content_class: meshelf_core::FileContentClass::File,
        };
        let cases = [
            ("at expiry", peer, photo_descriptor(), EXPIRES, "expired"),
            (
                "after expiry",
                peer,
                photo_descriptor(),
                EXPIRES + 1,
                "expired",
            ),
            (
                "third peer",
                DeviceId::new(),
                photo_descriptor(),
                NOW,
                "wrong_source",
            ),
            ("folder", peer, folder, NOW, "not_single_file"),
            (
                "text",
                peer,
                OfferDescriptor::text("not a photo").expect("text"),
                NOW,
                "not_single_file",
            ),
            ("empty file", peer, file_of(0), NOW, "not_single_file"),
            ("path as name", peer, escaping, NOW, "not_single_file"),
            (
                "too large",
                peer,
                file_of(MAX_CAPTURE_PHOTO_BYTES + 1),
                NOW,
                "too_large",
            ),
        ];
        for (case, source, descriptor, now, expected) in cases {
            assert_eq!(
                grant_label(&claim(source, descriptor, now)),
                expected,
                "{case}"
            );
            assert_eq!(
                store.get_capture_request(id).expect("read"),
                Some(armed.clone()),
                "{case} must leave the grant armed and unclaimed"
            );
        }
        let unknown = store
            .claim_capture_grant(
                CaptureRequestId::new(),
                peer,
                OfferId::new(),
                ActivationId::new(),
                photo_descriptor(),
                NOW,
            )
            .expect("claim");
        assert_eq!(unknown, CaptureGrantClaim::Unknown);
        // The refusals consumed nothing: the rightful announcement still wins at the last
        // millisecond and at the size limit.
        assert_eq!(
            grant_label(&claim(peer, file_of(MAX_CAPTURE_PHOTO_BYTES), EXPIRES - 1)),
            "claimed"
        );
    }

    #[test]
    fn a_pull_that_fails_after_its_claim_is_terminal_and_never_rearmed() {
        let (_directory, store) = open_store();
        let (claimed, _) = request_at(&store, At::Claimed);
        let id = claimed.request_id;
        let failed = applied(
            store
                .terminate_capture(
                    id,
                    CaptureTerminalCode::TransferFailed,
                    Some("connection reset".into()),
                )
                .expect("terminate"),
        );
        assert_eq!(
            label(&store.arm_capture_grant(id, PRESENTED).expect("arm")),
            "refused"
        );
        let again = store
            .claim_capture_grant(
                id,
                claimed.peer,
                OfferId::new(),
                ActivationId::new(),
                photo_descriptor(),
                NOW,
            )
            .expect("claim");
        assert_eq!(again, CaptureGrantClaim::NotArmed);
        assert_eq!(
            label(
                &store
                    .terminate_capture(id, CaptureTerminalCode::Cancelled, None)
                    .expect("terminate")
            ),
            "refused",
            "terminal is sticky"
        );
        assert_eq!(
            label(
                &store
                    .terminate_capture(id, CaptureTerminalCode::TransferFailed, None)
                    .expect("terminate")
            ),
            "unchanged",
            "repeating the same end is idempotent and keeps the first detail"
        );
        assert_eq!(store.get_capture_request(id).expect("read"), Some(failed));
    }

    #[test]
    fn completion_requires_the_claiming_activation_and_a_receipt_that_matches_the_claim() {
        let (_directory, store) = open_store();
        let (claimed, activation) = request_at(&store, At::Claimed);
        let id = claimed.request_id;
        assert_eq!(
            label(
                &store
                    .complete_capture(id, ActivationId::new(), receipt(&claimed))
                    .expect("complete")
            ),
            "refused"
        );
        let mut short = receipt(&claimed);
        short.bytes = PHOTO_BYTES - 1;
        assert!(store.complete_capture(id, activation, short).is_err());
        let mut elsewhere = receipt(&claimed);
        elsewhere.output_path = std::env::temp_dir().join("renamed (2).jpg");
        assert!(
            store.complete_capture(id, activation, elsewhere).is_err(),
            "a photo is completed only at the grant's exact output path"
        );
        assert_eq!(
            store.get_capture_request(id).expect("read"),
            Some(claimed.clone())
        );
        let completed = applied(
            store
                .complete_capture(id, activation, receipt(&claimed))
                .expect("complete"),
        );
        assert_eq!(completed.outcome(), Some(CaptureOutcome::COMPLETED));
    }

    #[test]
    fn a_repeated_capture_start_is_a_duplicate_and_a_reused_id_is_a_conflict() {
        let (_directory, store) = open_store();
        let original = request(DeviceId::new());
        let id = original.request_id;
        inserted(&store, original.clone());
        assert_eq!(
            store
                .insert_capture_request(original.clone())
                .expect("repeat"),
            CaptureRequestInsert::Duplicate(original.clone())
        );
        let armed = applied(store.arm_capture_grant(id, PRESENTED).expect("arm"));
        assert_eq!(
            store
                .insert_capture_request(original.clone())
                .expect("repeat"),
            CaptureRequestInsert::Duplicate(armed.clone()),
            "a retry after presentation names the same request and must not reset it"
        );
        let mut reused = original.clone();
        reused.purpose = "Photograph the serial number".to_owned();
        assert_eq!(
            store.insert_capture_request(reused).expect("reuse"),
            CaptureRequestInsert::Conflict
        );
        assert_eq!(store.get_capture_request(id).expect("read"), Some(armed));
        let mut pre_armed = request(original.peer);
        pre_armed.phase = CaptureRequestPhase::Armed {
            presented_at_unix_ms: PRESENTED,
        };
        assert!(
            store.insert_capture_request(pre_armed).is_err(),
            "a grant is armed only by a presentation, never at insert"
        );
        assert_eq!(store.read_capture_requests().expect("read").len(), 1);
    }

    #[test]
    fn a_ninth_live_request_is_refused_rather_than_grown() {
        let (_directory, store) = open_store();
        let live: Vec<CaptureRequestRecord> = (0..MAX_LIVE_CAPTURE_REQUESTS)
            .map(|_| inserted(&store, request(DeviceId::new())))
            .collect();
        let ninth = request(DeviceId::new());
        assert_eq!(
            store.insert_capture_request(ninth.clone()).expect("ninth"),
            CaptureRequestInsert::AtCapacity { live: 8, rows: 8 }
        );
        assert!(
            store
                .get_capture_request(ninth.request_id)
                .expect("read")
                .is_none()
        );
        applied(
            store
                .terminate_capture(live[0].request_id, CaptureTerminalCode::Cancelled, None)
                .expect("terminate"),
        );
        inserted(&store, ninth);
    }

    #[test]
    fn unreported_outcomes_are_kept_and_a_33rd_row_waits_until_one_is_reported() {
        let (_directory, store) = open_store();
        let finished: Vec<CaptureRequestId> = (0..MAX_CAPTURE_REQUEST_ROWS)
            .map(|_| {
                let (record, _) = request_at(&store, At::Terminal);
                record.request_id
            })
            .collect();
        let extra = request(DeviceId::new());
        assert_eq!(
            store.insert_capture_request(extra.clone()).expect("extra"),
            CaptureRequestInsert::AtCapacity { live: 0, rows: 32 },
            "an outcome nobody has read yet is never discarded to make room"
        );
        applied(store.mark_capture_reported(finished[5]).expect("report"));
        applied(store.mark_capture_reported(finished[9]).expect("report"));
        match store.insert_capture_request(extra).expect("extra") {
            CaptureRequestInsert::Inserted {
                pruned_reported, ..
            } => assert_eq!(pruned_reported, 1),
            other => panic!("{other:?}"),
        }
        let remaining: HashSet<CaptureRequestId> = store
            .read_capture_requests()
            .expect("read")
            .into_iter()
            .map(|row| row.request_id)
            .collect();
        assert_eq!(remaining.len(), MAX_CAPTURE_REQUEST_ROWS);
        assert!(
            !remaining.contains(&finished[5]),
            "the oldest reported row makes room"
        );
        assert!(
            remaining.contains(&finished[9]),
            "only as many as needed go"
        );
        assert_eq!(store.prune_reported_capture_requests().expect("prune"), 1);
        let unreported = finished
            .iter()
            .filter(|id| ![finished[5], finished[9]].contains(id))
            .all(|id| store.get_capture_request(*id).expect("read").is_some());
        assert!(unreported, "pruning removes reported rows only");
    }

    #[test]
    fn expiry_ends_unclaimed_requests_but_never_a_claimed_pull() {
        let (_directory, store) = open_store();
        let (awaiting, _) = request_at(&store, At::Awaiting);
        let (armed, _) = request_at(&store, At::Armed);
        let (claimed, _) = request_at(&store, At::Claimed);
        assert!(store.expire_due(EXPIRES - 1).expect("early").is_empty());
        let expired: HashSet<CaptureRequestId> = store
            .expire_due(EXPIRES)
            .expect("expire")
            .into_iter()
            .map(|row| row.request_id)
            .collect();
        assert_eq!(
            expired,
            HashSet::from([awaiting.request_id, armed.request_id])
        );
        for id in [awaiting.request_id, armed.request_id] {
            let row = store.get_capture_request(id).expect("read").expect("row");
            assert_eq!(
                row.phase,
                CaptureRequestPhase::Terminal {
                    code: CaptureTerminalCode::Expired,
                    detail: None
                }
            );
        }
        assert_eq!(
            store.get_capture_request(claimed.request_id).expect("read"),
            Some(claimed)
        );
        let (late, _) = request_at(&store, At::Awaiting);
        assert_eq!(
            label(
                &store
                    .arm_capture_grant(late.request_id, EXPIRES)
                    .expect("arm")
            ),
            "refused",
            "a presentation acknowledged at expiry arms nothing"
        );
    }

    #[test]
    fn requester_restart_ends_every_live_request_and_resumes_no_pull() {
        let (_directory, store) = open_store();
        let now = CREATED + 100_000;
        let expired_request = |store: &RedbV2Store| {
            let mut record = request(DeviceId::new());
            record.created_at_unix_ms = CREATED - 100_000;
            record.grant.expires_at_unix_ms = CREATED + 80_000;
            inserted(store, record)
        };
        let (awaiting, _) = request_at(&store, At::Awaiting);
        let (armed, _) = request_at(&store, At::Armed);
        let expired_awaiting = expired_request(&store);
        let expired_armed = expired_request(&store);
        applied(
            store
                .arm_capture_grant(expired_armed.request_id, PRESENTED)
                .expect("arm"),
        );
        let (claimed, activation) = request_at(&store, At::Claimed);
        let (reported, _) = request_at(&store, At::Completed);
        applied(
            store
                .mark_capture_reported(reported.request_id)
                .expect("report"),
        );
        let (unreported, _) = request_at(&store, At::Completed);
        let (declined, _) = request_at(&store, At::Terminal);

        let report = store
            .reconcile_capture_requests_at_startup(now)
            .expect("reconcile");
        let ids = |rows: &[CaptureRequestRecord]| {
            rows.iter()
                .map(|row| row.request_id)
                .collect::<HashSet<_>>()
        };
        assert_eq!(
            ids(&report.cancel),
            HashSet::from([awaiting.request_id, armed.request_id])
        );
        assert_eq!(
            ids(&report.restarted_after_expiry),
            HashSet::from([expired_awaiting.request_id, expired_armed.request_id])
        );
        assert_eq!(ids(&report.uncertain), HashSet::from([claimed.request_id]));
        assert_eq!(report.pruned_reported, 1);

        let restarted = CaptureRequestPhase::Terminal {
            code: CaptureTerminalCode::ResidentRestarted,
            detail: None,
        };
        let uncertain = CaptureRequestPhase::Terminal {
            code: CaptureTerminalCode::UncertainNoReplay,
            detail: None,
        };
        let expected = [
            (awaiting.request_id, Some(restarted.clone())),
            (armed.request_id, Some(restarted.clone())),
            (expired_awaiting.request_id, Some(restarted.clone())),
            (expired_armed.request_id, Some(restarted)),
            (claimed.request_id, Some(uncertain)),
            (reported.request_id, None),
            (unreported.request_id, Some(unreported.phase.clone())),
            (declined.request_id, Some(declined.phase.clone())),
        ];
        for (id, phase) in expected {
            assert_eq!(
                store
                    .get_capture_request(id)
                    .expect("read")
                    .map(|row| row.phase),
                phase,
                "{id}"
            );
        }
        // The claimed pull is over: a late announcement cannot claim it and a late publication
        // cannot complete it.
        let late = store
            .claim_capture_grant(
                claimed.request_id,
                claimed.peer,
                OfferId::new(),
                ActivationId::new(),
                photo_descriptor(),
                NOW,
            )
            .expect("claim");
        assert_eq!(late, CaptureGrantClaim::NotArmed);
        assert_eq!(
            label(
                &store
                    .complete_capture(claimed.request_id, activation, receipt(&claimed))
                    .expect("complete")
            ),
            "refused"
        );
        let again = store
            .reconcile_capture_requests_at_startup(now)
            .expect("reconcile again");
        assert_eq!(again, CaptureRequestReconciliation::default());
    }

    type SourceOp =
        fn(&RedbV2Store, &CaptureSourceRecord, &CapturedPhoto, ActivationId) -> &'static str;

    #[test]
    fn phone_transition_legality_matrix() {
        const PHASES: [SourceAt; 7] = [
            SourceAt::Presented,
            SourceAt::Captured,
            SourceAt::Announced,
            SourceAt::Claimed,
            SourceAt::Delivered,
            SourceAt::Uncertain,
            SourceAt::Terminal,
        ];
        let matrix: [(&str, SourceOp, [&str; 7], &str); 6] = [
            (
                "attach",
                |store, record, photo, _| {
                    label(
                        &store
                            .attach_captured(record.request_id, photo.clone())
                            .expect("attach"),
                    )
                },
                [
                    "applied",
                    "unchanged",
                    "refused",
                    "refused",
                    "refused",
                    "refused",
                    "refused",
                ],
                "captured",
            ),
            (
                "announce",
                |store, record, _, _| {
                    label(
                        &store
                            .mark_capture_announced(record.request_id)
                            .expect("announce"),
                    )
                },
                [
                    "refused",
                    "applied",
                    "unchanged",
                    "refused",
                    "refused",
                    "refused",
                    "refused",
                ],
                "announced",
            ),
            (
                "claim",
                |store, record, photo, _| {
                    source_claim_label(
                        &store
                            .claim_capture_source(
                                photo.offer_id,
                                record.requester,
                                ActivationId::new(),
                            )
                            .expect("claim"),
                    )
                },
                [
                    "unknown",
                    "not_announced",
                    "claimed",
                    "already_claimed",
                    "unknown",
                    "unknown",
                    "unknown",
                ],
                "claimed",
            ),
            (
                "deliver",
                |store, record, _, activation| {
                    label(
                        &store
                            .mark_capture_delivered(record.request_id, activation, 1, PHOTO_BYTES)
                            .expect("deliver"),
                    )
                },
                [
                    "refused",
                    "refused",
                    "refused",
                    "applied",
                    "unchanged",
                    "refused",
                    "refused",
                ],
                "delivered",
            ),
            (
                "uncertain",
                |store, record, _, _| {
                    label(
                        &store
                            .mark_capture_uncertain(record.request_id, DELETE_DEADLINE)
                            .expect("uncertain"),
                    )
                },
                [
                    "refused",
                    "refused",
                    "refused",
                    "applied",
                    "refused",
                    "unchanged",
                    "refused",
                ],
                "uncertain_no_replay",
            ),
            (
                "terminate",
                |store, record, _, _| {
                    label(
                        &store
                            .terminate_capture_source(
                                record.request_id,
                                CaptureSourceTerminalCode::Cancelled,
                            )
                            .expect("terminate"),
                    )
                },
                [
                    "applied", "applied", "applied", "refused", "refused", "refused", "refused",
                ],
                "terminal",
            ),
        ];
        for (operation, run, expected, applied_phase) in matrix {
            for (at, want) in PHASES.into_iter().zip(expected) {
                let (_directory, store) = open_store();
                let (record, photo, activation) = source_at(&store, at);
                let seen = run(&store, &record, &photo, activation);
                assert_eq!(seen, want, "{operation} from {at:?}");
                let after = store
                    .get_capture_source(record.request_id)
                    .expect("read")
                    .expect("row");
                if matches!(seen, "applied" | "claimed") {
                    assert_eq!(
                        source_phase_name(&after.phase),
                        applied_phase,
                        "{operation} from {at:?}"
                    );
                } else {
                    assert_eq!(after, record, "{operation} from {at:?} must change nothing");
                }
            }
        }
    }

    #[test]
    fn two_fetches_racing_for_one_photo_serve_it_exactly_once() {
        let (_directory, store) = open_store();
        for round in 0..32 {
            let (record, photo, _) = source_at(&store, SourceAt::Announced);
            let barrier = Barrier::new(2);
            let claims: Vec<(ActivationId, CaptureSourceClaim)> = thread::scope(|scope| {
                let racers: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            let activation = ActivationId::new();
                            barrier.wait();
                            let claim = store
                                .claim_capture_source(photo.offer_id, record.requester, activation)
                                .expect("claim");
                            (activation, claim)
                        })
                    })
                    .collect();
                racers
                    .into_iter()
                    .map(|racer| racer.join().expect("racer"))
                    .collect()
            });
            let winners: Vec<ActivationId> = claims
                .iter()
                .filter(|(_, claim)| matches!(claim, CaptureSourceClaim::Claimed(_)))
                .map(|(activation, _)| *activation)
                .collect();
            assert_eq!(winners.len(), 1, "round {round}: {claims:?}");
            assert!(
                claims
                    .iter()
                    .any(|(_, claim)| *claim == CaptureSourceClaim::AlreadyClaimed),
                "round {round}: {claims:?}"
            );
            let stored = store
                .get_capture_source(record.request_id)
                .expect("read")
                .expect("row");
            assert_eq!(
                stored.phase,
                CaptureSourcePhase::Claimed {
                    photo: photo.clone(),
                    activation_id: winners[0],
                }
            );
            applied(
                store
                    .mark_capture_delivered(record.request_id, winners[0], 1, PHOTO_BYTES)
                    .expect("deliver"),
            );
        }
        assert!(store.read_capture_sources().expect("read").len() <= MAX_CAPTURE_SOURCE_TOMBSTONES);
    }

    #[test]
    fn a_photo_is_served_at_most_once_and_only_to_its_requester() {
        let (_directory, store) = open_store();
        let (announced, photo, _) = source_at(&store, SourceAt::Announced);
        let id = announced.request_id;
        let third_peer = store
            .claim_capture_source(photo.offer_id, DeviceId::new(), ActivationId::new())
            .expect("claim");
        assert_eq!(third_peer, CaptureSourceClaim::WrongRequester);
        assert_eq!(
            store.get_capture_source(id).expect("read"),
            Some(announced.clone())
        );

        let first = ActivationId::new();
        assert!(matches!(
            store
                .claim_capture_source(photo.offer_id, announced.requester, first)
                .expect("claim"),
            CaptureSourceClaim::Claimed(_)
        ));
        for retry in [first, ActivationId::new()] {
            assert_eq!(
                store
                    .claim_capture_source(photo.offer_id, announced.requester, retry)
                    .expect("claim"),
                CaptureSourceClaim::AlreadyClaimed,
                "a repeated fetch, even from the same activation, is never served"
            );
        }
        applied(
            store
                .mark_capture_delivered(id, first, 1, PHOTO_BYTES)
                .expect("deliver"),
        );
        assert!(
            store
                .get_capture_source_by_offer(photo.offer_id)
                .expect("read")
                .is_none()
        );
        assert_eq!(
            store
                .claim_capture_source(photo.offer_id, announced.requester, ActivationId::new())
                .expect("claim"),
            CaptureSourceClaim::Unknown
        );
        let tombstone = store.get_capture_source(id).expect("read").expect("row");
        let encoded = serde_json::to_string(&tombstone).expect("encode");
        assert!(
            !encoded.contains("agent-captures"),
            "a delivered tombstone keeps no path: {encoded}"
        );
    }

    #[test]
    fn a_receipt_that_does_not_match_the_photo_is_never_recorded_as_delivered() {
        let (_directory, store) = open_store();
        let (claimed, photo, activation) = source_at(&store, SourceAt::Claimed);
        let id = claimed.request_id;
        let cases = [
            ("another activation", ActivationId::new(), 1, PHOTO_BYTES),
            ("no file", activation, 0, PHOTO_BYTES),
            ("two files", activation, 2, PHOTO_BYTES),
            ("short", activation, 1, PHOTO_BYTES - 1),
            ("long", activation, 1, PHOTO_BYTES + 1),
        ];
        for (case, receipt_activation, files, bytes) in cases {
            assert_eq!(
                label(
                    &store
                        .mark_capture_delivered(id, receipt_activation, files, bytes)
                        .expect("deliver")
                ),
                "refused",
                "{case}"
            );
            assert_eq!(
                store.get_capture_source(id).expect("read"),
                Some(claimed.clone()),
                "{case}"
            );
        }
        // The receipt is lost: the photo is uncertain and never served or announced again.
        applied(
            store
                .mark_capture_uncertain(id, DELETE_DEADLINE)
                .expect("uncertain"),
        );
        assert_eq!(
            label(&store.mark_capture_announced(id).expect("announce")),
            "refused"
        );
        assert_eq!(
            store
                .claim_capture_source(photo.offer_id, claimed.requester, ActivationId::new())
                .expect("claim"),
            CaptureSourceClaim::Unknown
        );
        assert_eq!(
            label(
                &store
                    .mark_capture_delivered(id, activation, 1, PHOTO_BYTES)
                    .expect("deliver")
            ),
            "refused",
            "a late receipt does not turn an uncertain photo into a delivered one"
        );
    }

    #[test]
    fn an_uncertain_photo_is_deleted_at_its_deadline_as_expired_unconfirmed_never_as_delivered() {
        let (_directory, store) = open_store();
        let (uncertain, _, _) = source_at(&store, SourceAt::Uncertain);
        let id = uncertain.request_id;
        assert_eq!(
            store
                .prune_capture_tombstones(DELETE_DEADLINE - 1)
                .expect("prune"),
            CaptureTombstonePrune::default()
        );
        assert_eq!(store.get_capture_source(id).expect("read"), Some(uncertain));
        let pruned = store
            .prune_capture_tombstones(DELETE_DEADLINE)
            .expect("prune");
        let unconfirmed = CaptureSourcePhase::Terminal {
            code: CaptureSourceTerminalCode::ExpiredUnconfirmed,
        };
        assert_eq!(pruned.expired_unconfirmed.len(), 1);
        assert_eq!(pruned.expired_unconfirmed[0].request_id, id);
        assert_eq!(pruned.expired_unconfirmed[0].phase, unconfirmed);
        assert_eq!(
            store
                .get_capture_source(id)
                .expect("read")
                .expect("row")
                .phase,
            unconfirmed
        );
        let (live, _, _) = source_at(&store, SourceAt::Presented);
        assert!(
            store
                .terminate_capture_source(
                    live.request_id,
                    CaptureSourceTerminalCode::ExpiredUnconfirmed
                )
                .is_err(),
            "only the deadline may record a photo as expired-unconfirmed"
        );
    }

    #[test]
    fn a_phone_status_ends_only_an_unclaimed_request_and_leaves_a_claimed_one_exactly_as_it_was() {
        // Once a pull has claimed the grant it owns the outcome. The phase check and the write
        // are one transaction, so a status cannot end a request claimed after it was read.
        for (at, want) in [
            (At::Awaiting, "applied"),
            (At::Armed, "applied"),
            (At::Claimed, "refused"),
            (At::Completed, "refused"),
            (At::Terminal, "refused"),
        ] {
            let (_directory, store) = open_store();
            let (record, _) = request_at(&store, at);
            let before = store
                .get_capture_request(record.request_id)
                .expect("read")
                .expect("row");
            let seen = store
                .terminate_capture_unless_claimed(
                    record.request_id,
                    CaptureTerminalCode::RemoteFailed,
                    Some("camera-permission-denied".into()),
                )
                .expect("terminate");
            assert_eq!(label(&seen), want, "{at:?}");
            let after = store
                .get_capture_request(record.request_id)
                .expect("read")
                .expect("row");
            if want == "refused" {
                assert_eq!(after, before, "{at:?} must be left exactly as it was");
            } else {
                assert!(
                    matches!(
                        after.phase,
                        CaptureRequestPhase::Terminal {
                            code: CaptureTerminalCode::RemoteFailed,
                            ..
                        }
                    ),
                    "{at:?}"
                );
            }
        }

        let (_directory, store) = open_store();
        let (armed, _) = request_at(&store, At::Armed);
        applied(
            store
                .terminate_capture_unless_claimed(
                    armed.request_id,
                    CaptureTerminalCode::Declined,
                    None,
                )
                .expect("terminate"),
        );
        let repeat = store
            .terminate_capture_unless_claimed(armed.request_id, CaptureTerminalCode::Declined, None)
            .expect("repeat");
        assert_eq!(label(&repeat), "unchanged");
    }

    #[test]
    fn a_claimed_photo_whose_fetch_failed_before_fetch_complete_ends_failed_and_only_failed() {
        // The requester publishes only after receiving every byte, so a fetch that failed before
        // `FetchComplete` provably delivered nothing: the photo may be deleted at once. No other
        // word may end a claimed row, because a decline or cancel arriving mid-transfer must not
        // erase a photo the requester may already hold.
        for code in [
            CaptureSourceTerminalCode::Declined,
            CaptureSourceTerminalCode::Expired,
            CaptureSourceTerminalCode::Cancelled,
        ] {
            let (_directory, store) = open_store();
            let (claimed, _, _) = source_at(&store, SourceAt::Claimed);
            let seen = store
                .terminate_capture_source(claimed.request_id, code)
                .expect("terminate");
            assert_eq!(label(&seen), "refused", "{code:?} from claimed");
        }

        let (_directory, store) = open_store();
        let (claimed, photo, _) = source_at(&store, SourceAt::Claimed);
        let failed = applied(
            store
                .terminate_capture_source(claimed.request_id, CaptureSourceTerminalCode::Failed)
                .expect("terminate"),
        );
        assert_eq!(
            failed.phase,
            CaptureSourcePhase::Terminal {
                code: CaptureSourceTerminalCode::Failed
            }
        );
        assert_eq!(
            label(
                &store
                    .terminate_capture_source(claimed.request_id, CaptureSourceTerminalCode::Failed)
                    .expect("repeat")
            ),
            "unchanged"
        );
        // The failed row keeps no photo, so nothing can serve it again.
        assert_eq!(
            store
                .get_capture_source_by_offer(photo.offer_id)
                .expect("lookup"),
            None
        );

        // After `FetchComplete` the outcome is delivered or uncertain; neither becomes failed.
        for at in [SourceAt::Delivered, SourceAt::Uncertain] {
            let (_directory, store) = open_store();
            let (row, _, _) = source_at(&store, at);
            let seen = store
                .terminate_capture_source(row.request_id, CaptureSourceTerminalCode::Failed)
                .expect("terminate");
            assert_eq!(label(&seen), "refused", "failed from {at:?}");
        }
    }

    #[test]
    fn finished_phone_rows_are_bounded_at_eight_and_an_uncertain_photo_is_never_evicted_early() {
        let (_directory, store) = open_store();
        let mut delivered = Vec::new();
        for _ in 0..12 {
            let (record, _, _) = source_at(&store, SourceAt::Delivered);
            delivered.push(record.request_id);
            let rows = store.read_capture_sources().expect("read");
            assert!(
                rows.len() <= MAX_CAPTURE_SOURCE_TOMBSTONES,
                "{}",
                rows.len()
            );
        }
        let kept: HashSet<CaptureRequestId> = store
            .read_capture_sources()
            .expect("read")
            .into_iter()
            .map(|row| row.request_id)
            .collect();
        assert_eq!(
            kept,
            delivered[4..].iter().copied().collect(),
            "the newest eight stay"
        );

        for _ in 0..MAX_CAPTURE_SOURCE_TOMBSTONES {
            source_at(&store, SourceAt::Uncertain);
        }
        let rows = store.read_capture_sources().expect("read");
        assert_eq!(rows.len(), MAX_CAPTURE_SOURCE_TOMBSTONES);
        assert!(rows.iter().all(|row| is_pinned(&row.phase)));
        let blocked = source_request(DeviceId::new());
        assert_eq!(
            store.present_capture(blocked.clone()).expect("present"),
            CapturePresentation::AtCapacity,
            "eight photos awaiting their deadline pin every slot; a ninth request is refused"
        );
        assert!(
            store
                .get_capture_source(blocked.request_id)
                .expect("read")
                .is_none()
        );
        let pruned = store
            .prune_capture_tombstones(DELETE_DEADLINE)
            .expect("prune");
        assert_eq!(
            pruned.expired_unconfirmed.len(),
            MAX_CAPTURE_SOURCE_TOMBSTONES
        );
        assert_eq!(pruned.removed, 0);
        match store.present_capture(blocked).expect("present") {
            CapturePresentation::Presented {
                pruned_tombstones, ..
            } => assert_eq!(pruned_tombstones, 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_phone_holds_one_live_request_and_repeats_its_answer_to_duplicates() {
        let (_directory, store) = open_store();
        let requester = DeviceId::new();
        let first = source_request(requester);
        let id = first.request_id;
        assert_eq!(
            store.present_capture(first.clone()).expect("present"),
            CapturePresentation::Presented {
                record: first.clone(),
                pruned_tombstones: 0
            }
        );
        assert_eq!(
            store.present_capture(first.clone()).expect("repeat"),
            CapturePresentation::Duplicate(CaptureSourcePhase::Presented)
        );
        let mut reused = first.clone();
        reused.purpose = "Photograph the serial number".to_owned();
        assert_eq!(
            store.present_capture(reused).expect("reuse"),
            CapturePresentation::Conflict
        );
        let second = source_request(requester);
        assert_eq!(
            store.present_capture(second.clone()).expect("second"),
            CapturePresentation::Busy
        );
        let photo = photo();
        applied(store.attach_captured(id, photo.clone()).expect("attach"));
        assert_eq!(
            store.present_capture(first.clone()).expect("repeat"),
            CapturePresentation::Duplicate(CaptureSourcePhase::Captured {
                photo: photo.clone()
            }),
            "a repeated request never reopens the camera for a photo already taken"
        );
        assert_eq!(
            store.present_capture(second.clone()).expect("second"),
            CapturePresentation::Busy
        );
        applied(store.mark_capture_announced(id).expect("announce"));
        let activation = ActivationId::new();
        assert!(matches!(
            store
                .claim_capture_source(photo.offer_id, requester, activation)
                .expect("claim"),
            CaptureSourceClaim::Claimed(_)
        ));
        assert_eq!(
            store.present_capture(second.clone()).expect("second"),
            CapturePresentation::Busy,
            "a photo being served is still live"
        );
        applied(
            store
                .mark_capture_delivered(id, activation, 1, PHOTO_BYTES)
                .expect("deliver"),
        );
        assert_eq!(
            store.present_capture(first).expect("repeat"),
            CapturePresentation::Duplicate(CaptureSourcePhase::Delivered)
        );
        presented(&store, second);
        let mut captured = source_request(requester);
        captured.phase = CaptureSourcePhase::Captured { photo };
        assert!(store.present_capture(captured).is_err());
    }

    #[test]
    fn phone_restart_represents_only_an_untaken_request_and_never_resumes_a_served_one() {
        let failed = CaptureSourcePhase::Terminal {
            code: CaptureSourceTerminalCode::Failed,
        };
        let expired = CaptureSourcePhase::Terminal {
            code: CaptureSourceTerminalCode::Expired,
        };
        let uncertain = CaptureSourcePhase::UncertainNoReplay {
            deadline_unix_ms: DELETE_DEADLINE,
            path: photo().path,
        };
        // (starting phase, restart time, what reconciliation reports, the phase afterwards;
        // `None` means unchanged)
        let cases = [
            (SourceAt::Presented, NOW, "represent", None),
            (
                SourceAt::Presented,
                EXPIRES,
                "withdraw",
                Some(expired.clone()),
            ),
            (SourceAt::Captured, NOW, "withdraw", Some(failed.clone())),
            (
                SourceAt::Captured,
                EXPIRES,
                "withdraw",
                Some(expired.clone()),
            ),
            (SourceAt::Announced, NOW, "withdraw", Some(failed)),
            (SourceAt::Announced, EXPIRES, "withdraw", Some(expired)),
            (SourceAt::Claimed, NOW, "uncertain", Some(uncertain.clone())),
            (SourceAt::Claimed, EXPIRES, "uncertain", Some(uncertain)),
            (SourceAt::Delivered, NOW, "untouched", None),
            (SourceAt::Uncertain, NOW, "untouched", None),
            (SourceAt::Terminal, NOW, "untouched", None),
        ];
        for (at, now, bucket, phase) in cases {
            let (_directory, store) = open_store();
            let (record, photo, _) = source_at(&store, at);
            let report = store
                .reconcile_capture_sources_at_startup(now)
                .expect("reconcile");
            let after = store
                .get_capture_source(record.request_id)
                .expect("read")
                .expect("row");
            assert_eq!(
                after.phase,
                phase.unwrap_or_else(|| record.phase.clone()),
                "{at:?} at {now}"
            );
            let observed = match (
                &report.represent,
                report.withdraw.as_slice(),
                report.uncertain.as_slice(),
            ) {
                (Some(represent), [], []) if *represent == after => "represent",
                (None, [withdrawn], []) if *withdrawn == after => "withdraw",
                (None, [], [uncertain]) if *uncertain == after => "uncertain",
                (None, [], []) => "untouched",
                _ => "unexpected",
            };
            assert_eq!(observed, bucket, "{at:?} at {now}: {report:?}");
            let claim = store
                .claim_capture_source(photo.offer_id, record.requester, ActivationId::new())
                .expect("claim");
            assert!(
                !matches!(claim, CaptureSourceClaim::Claimed(_)),
                "{at:?} at {now}: nothing reconciled is served afterwards"
            );
        }
    }

    #[test]
    fn an_agents_photo_cannot_evict_a_users_shelf_item() {
        let (_directory, store) = open_store();
        let peer = DeviceId::new();
        let card = |text: &str| {
            OfferCardInput::new(
                peer,
                OfferId::new(),
                OfferDescriptor::text(text).expect("descriptor"),
                CardAvailability::Available,
            )
        };
        let source = |text: &str| {
            OfferSourceInput::new(
                OfferId::new(),
                OfferDescriptor::text(text).expect("descriptor"),
                HashSet::from([peer]),
                OfferSource::Text {
                    text: text.to_owned(),
                },
            )
        };
        for index in 0..V2_MAX_LIVE_ENTRIES {
            let text = format!("kept by the user {index}");
            store.insert_offer_source(source(&text)).expect("source");
            store.insert_offer_card(card(&text)).expect("card");
        }
        let shelf = store.read_offer_shelf().expect("shelf");
        let sources = store.read_offer_sources().expect("sources");
        assert_eq!(shelf.len(), 10);
        assert_eq!(sources.len(), 10);

        // More captures than the shelf has slots, on both sides, through every phase.
        for _ in 0..=V2_MAX_LIVE_ENTRIES {
            let (completed, _) = request_at(&store, At::Completed);
            applied(
                store
                    .mark_capture_reported(completed.request_id)
                    .expect("report"),
            );
            source_at(&store, SourceAt::Delivered);
        }
        request_at(&store, At::Claimed);
        source_at(&store, SourceAt::Announced);
        store.prune_reported_capture_requests().expect("prune");
        store.prune_capture_tombstones(NOW).expect("prune");
        store.expire_due(EXPIRES).expect("expire");
        store
            .reconcile_capture_requests_at_startup(EXPIRES)
            .expect("reconcile");
        store
            .reconcile_capture_sources_at_startup(EXPIRES)
            .expect("reconcile");

        assert_eq!(
            store.read_offer_shelf().expect("shelf"),
            shelf,
            "same cards, same sequences"
        );
        assert_eq!(store.read_offer_sources().expect("sources"), sources);
        // The captures never counted toward the ten: the next user card displaces exactly one
        // card, the user's oldest, just as it would have with no capture at all.
        let next_card = store.insert_offer_card(card("next")).expect("card");
        assert_eq!(next_card.purged, 1);
        let after = store.read_offer_shelf().expect("shelf");
        assert_eq!(after.len(), 10);
        assert!(!after.contains(shelf.last().expect("oldest card")));
        assert!(shelf[..9].iter().all(|kept| after.contains(kept)));
        let next_source = store.insert_offer_source(source("next")).expect("source");
        assert_eq!(next_source.purged, 1);
        let after = store.read_offer_sources().expect("sources");
        assert!(!after.contains(sources.last().expect("oldest source")));
        assert!(sources[..9].iter().all(|kept| after.contains(kept)));
    }

    #[test]
    fn capture_rows_survive_closing_and_reopening_the_store() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("meshelf.redb");
        let (claimed, announced, photo) = {
            let store = RedbV2Store::open(&path).expect("open");
            let (claimed, _) = request_at(&store, At::Claimed);
            let (announced, photo, _) = source_at(&store, SourceAt::Announced);
            (claimed, announced, photo)
        };
        let reopened = RedbV2Store::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .get_capture_request(claimed.request_id)
                .expect("read"),
            Some(claimed.clone())
        );
        assert_eq!(
            reopened
                .get_capture_source_by_offer(photo.offer_id)
                .expect("read"),
            Some(announced.clone())
        );
        // A claim committed before the restart still excludes every later one.
        let late = reopened
            .claim_capture_grant(
                claimed.request_id,
                claimed.peer,
                OfferId::new(),
                ActivationId::new(),
                photo_descriptor(),
                NOW,
            )
            .expect("claim");
        assert!(matches!(late, CaptureGrantClaim::AlreadyClaimed { .. }));
        assert!(matches!(
            reopened
                .claim_capture_source(photo.offer_id, announced.requester, ActivationId::new())
                .expect("claim"),
            CaptureSourceClaim::Claimed(_)
        ));
    }
}
