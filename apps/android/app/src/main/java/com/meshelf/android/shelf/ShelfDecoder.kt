package com.meshelf.android.shelf

/** Why native JSON was refused. [invalidRecords] counts card records that failed validation. */
data class DecodeFailure(val kind: Kind, val invalidRecords: Int, val detail: String) {
    enum class Kind { INVALID, UNSUPPORTED_SNAPSHOT_SCHEMA }
}

sealed class Decoded<out T> {
    data class Ok<T>(val value: T) : Decoded<T>()
    data class Rejected(val failure: DecodeFailure) : Decoded<Nothing>()
}

/**
 * Fail-closed decoder for the ABI-8 JSON contract (schemaVersion 2). A missing required field, a
 * wrong type, an unknown enum, more than ten cards or a duplicate key rejects the whole value; there
 * is no default, zero-fill or dropped record. Nullable fields must be present as explicit `null`.
 * Only a malformed `peerObservation` is contained: the cards stay and peer status is unreadable.
 */
object ShelfDecoder {
    const val SCHEMA_VERSION = 2L

    private class Violation(val kind: DecodeFailure.Kind, message: String) : Exception(message)

    fun snapshot(json: String): Decoded<ShelfSnapshot> = decode(json) { root ->
        schema(root, "snapshot")
        snapshotObject(root, "snapshot")
    }

    fun refresh(json: String): Decoded<RefreshResult> = decode(json) { root ->
        schema(root, "refresh")
        val newItems = root.long("newItems")
        val snapshot = snapshotObject(root.obj("snapshot"), "refresh.snapshot").let { snap ->
            // The embedded observation is this refresh's; anything else is not a usable report.
            val status = snap.peerStatus
            if (status is PeerStatus.Observed && status.observation.trigger == PeerTrigger.REFRESH) snap
            else snap.copy(peerStatus = PeerStatus.Unreadable)
        }
        RefreshResult(newItems, snapshot)
    }

    fun announce(json: String): Decoded<AnnounceResult> = decode(json) { root ->
        schema(root, "announce")
        val peers = peerList(root.array("peers"), "announce.peers")
        val result = AnnounceResult(
            offerId = root.nonBlank("offerId"),
            localStored = root.bool("localStored"),
            addedCount = root.long("addedCount"),
            unavailableCount = root.long("unavailableCount"),
            refusedCount = root.long("refusedCount"),
            peers = peers,
        )
        val stored = peers.count { it.outcome == PeerOutcome.STORED }.toLong()
        val refused = peers.count { it.outcome == PeerOutcome.REFUSED }.toLong()
        val unavailable = peers.count { it.reachability == PeerReachability.UNAVAILABLE }.toLong()
        if (result.addedCount != stored || result.refusedCount != refused || result.unavailableCount != unavailable) {
            invalid("announce counts disagree with per-peer outcomes")
        }
        result
    }

    fun activation(json: String): Decoded<ActivationResult> = decode(json) { root ->
        schema(root, "activation")
        val status = root.enum<ActivationStatus>("status")
        val code = root.enum<ActivationCode>("code")
        if ((status == ActivationStatus.COMPLETED) != (code == ActivationCode.COMPLETED)) {
            invalid("activation status $status disagrees with code $code")
        }
        ActivationResult(
            key = ShelfKey(root.nonBlank("sourceDevice"), root.nonBlank("offerId")),
            action = root.enum("action"),
            status = status,
            code = code,
            filesProcessed = root.long("filesProcessed"),
            bytesProcessed = root.long("bytesProcessed"),
            detail = root.nullableString("detail"),
        )
    }

    private fun <T> decode(json: String, block: (Obj) -> T): Decoded<T> = try {
        val root = StrictJson.parse(json) as? Map<*, *> ?: invalid("root is not an object")
        Decoded.Ok(block(Obj(root, "")))
    } catch (e: CardViolations) {
        Decoded.Rejected(DecodeFailure(e.kind, e.count, e.message ?: "invalid card"))
    } catch (e: Violation) {
        Decoded.Rejected(DecodeFailure(e.kind, 0, e.message ?: "invalid"))
    } catch (e: StrictJson.Malformed) {
        Decoded.Rejected(DecodeFailure(DecodeFailure.Kind.INVALID, 0, "malformed json: ${e.message}"))
    } catch (e: IllegalArgumentException) {
        Decoded.Rejected(DecodeFailure(DecodeFailure.Kind.INVALID, 0, e.message ?: "invalid"))
    }

    private class CardViolations(val kind: DecodeFailure.Kind, val count: Int, message: String) : Exception(message)

    private fun schema(root: Obj, what: String) {
        val version = root.long("schemaVersion", min = Long.MIN_VALUE)
        if (version != SCHEMA_VERSION) unsupported("$what schemaVersion $version != $SCHEMA_VERSION")
    }

    private fun snapshotObject(root: Obj, path: String): ShelfSnapshot {
        val ready = root.bool("ready")
        val completeness = root.enum<ShelfCompleteness>("completeness")
        val localName = root.nonBlank("localDisplayName")
        val rows = root.array("cards")
        if (rows.size > ShelfSnapshot.MAX_CARDS) invalid("$path has ${rows.size} cards (max ${ShelfSnapshot.MAX_CARDS})")
        val cards = ArrayList<ShelfCard>(rows.size)
        var failures = 0
        var unsupported = false
        var firstDetail: String? = null
        rows.forEachIndexed { index, row ->
            try {
                cards += card(Obj(row as? Map<*, *> ?: invalid("card is not an object"), "$path.cards[$index]"))
            } catch (e: Violation) {
                failures += 1
                unsupported = unsupported || e.kind == DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA
                if (firstDetail == null) firstDetail = e.message
            } catch (e: IllegalArgumentException) {
                failures += 1
                if (firstDetail == null) firstDetail = "$path.cards[$index]: ${e.message}"
            }
        }
        if (failures > 0) {
            val kind = if (unsupported) DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA else DecodeFailure.Kind.INVALID
            throw CardViolations(kind, failures, firstDetail ?: "invalid card")
        }
        if (cards.map { it.key }.toSet().size != cards.size) invalid("$path has duplicate (sourceDevice, offerId)")
        if (cards.zipWithNext().any { (newer, older) -> newer.shelfSequence < older.shelfSequence }) {
            invalid("$path cards are not newest first by shelfSequence")
        }
        val peerStatus = try {
            if (!root.has("peerObservation")) invalid("missing peerObservation")
            root.nullableObj("peerObservation")?.let { PeerStatus.Observed(observation(it)) } ?: PeerStatus.None
        } catch (_: Violation) {
            PeerStatus.Unreadable
        } catch (_: IllegalArgumentException) {
            PeerStatus.Unreadable
        }
        return ShelfSnapshot(ready, completeness, localName, cards, peerStatus)
    }

    private fun card(o: Obj): ShelfCard {
        val kind = o.enum<ShelfKind>("kind")
        val availability = o.enum<ShelfAvailability>("availability")
        val actions = o.array("supportedActions").mapIndexed { i, raw ->
            enumValue<ActivationAction>(raw as? String ?: invalid("${o.path}.supportedActions[$i] is not a string"), "${o.path}.supportedActions[$i]")
        }
        if (actions.toSet().size != actions.size) invalid("${o.path}.supportedActions has duplicates")
        if (actions.isNotEmpty() && availability != ShelfAvailability.READY) {
            invalid("${o.path} lists actions while $availability")
        }
        if (actions.isEmpty() && availability == ShelfAvailability.READY) {
            invalid("${o.path} is READY with no supported actions")
        }
        val allowed = when (kind) {
            ShelfKind.TEXT -> listOf(ActivationAction.COPY_TEXT)
            ShelfKind.FILE, ShelfKind.PHOTO -> listOf(ActivationAction.SHARE_FILE, ActivationAction.SAVE_FILE)
            ShelfKind.FOLDER -> emptyList()
        }
        if (!actions.all { it in allowed } || actions != allowed.filter { it in actions }) {
            invalid("${o.path} actions $actions are not an ordered subset of $allowed for $kind")
        }
        if (kind == ShelfKind.FOLDER && availability != ShelfAvailability.UNSUPPORTED) {
            invalid("${o.path} folder card must be UNSUPPORTED")
        }
        if (!o.has("activeOperation")) invalid("${o.path} missing activeOperation")
        if (o.raw("activeOperation") != null) unsupported("${o.path}.activeOperation is reserved in ABI 8")
        val preview = o.string("preview")
        if (preview.toByteArray(Charsets.UTF_8).size > ShelfCard.MAX_PREVIEW_UTF8_BYTES) invalid("${o.path}.preview exceeds O-015")
        return ShelfCard(
            key = ShelfKey(o.nonBlank("sourceDevice"), o.nonBlank("offerId")),
            sourceDisplayName = o.nonBlank("sourceDisplayName"),
            ownership = o.enum("ownership"),
            kind = kind,
            displayName = o.string("displayName"),
            preview = preview,
            byteLength = o.long("byteLength"),
            shelfSequence = o.long("shelfSequence"),
            availability = availability,
            supportedActions = actions,
            lastAttempt = o.nullableObj("lastAttempt")?.let { a ->
                LastAttempt(
                    code = a.enum("code"),
                    attemptSequence = a.long("attemptSequence"),
                    filesProcessed = a.long("filesProcessed"),
                    bytesProcessed = a.long("bytesProcessed"),
                    detail = a.nullableString("detail"),
                )
            },
        )
    }

    private fun observation(o: Obj): PeerObservation =
        PeerObservation(o.enum("trigger"), peerList(o.array("peers"), "${o.path}.peers"))

    private fun peerList(rows: List<Any?>, path: String): List<PeerEntry> {
        val peers = rows.mapIndexed { i, row ->
            val p = Obj(row as? Map<*, *> ?: invalid("$path[$i] is not an object"), "$path[$i]")
            val entry = PeerEntry(p.nonBlank("deviceId"), p.nonBlank("displayName"), p.enum("reachability"), p.enum("outcome"))
            val reachable = entry.outcome !in setOf(PeerOutcome.TRANSPORT_FAILED, PeerOutcome.NO_ADDRESS)
            if (reachable != (entry.reachability == PeerReachability.REACHABLE)) {
                invalid("$path[$i] outcome ${entry.outcome} disagrees with ${entry.reachability}")
            }
            entry
        }
        if (peers.map { it.deviceId }.toSet().size != peers.size) invalid("$path has duplicate deviceId")
        return peers
    }

    private fun invalid(message: String): Nothing = throw Violation(DecodeFailure.Kind.INVALID, message)
    private fun unsupported(message: String): Nothing =
        throw Violation(DecodeFailure.Kind.UNSUPPORTED_SNAPSHOT_SCHEMA, message)

    private inline fun <reified E : Enum<E>> enumValue(raw: String, path: String): E =
        enumValues<E>().firstOrNull { it.name == raw } ?: unsupported("$path has unknown value '$raw'")

    private class Obj(val map: Map<*, *>, val path: String) {
        fun has(name: String) = map.containsKey(name)
        fun raw(name: String): Any? {
            if (!map.containsKey(name)) invalid("missing $path.$name")
            return map[name]
        }
        fun string(name: String): String = raw(name) as? String ?: invalid("$path.$name is not a string")
        fun nonBlank(name: String): String = string(name).also { if (it.isBlank()) invalid("$path.$name is blank") }
        fun nullableString(name: String): String? = when (val v = raw(name)) {
            null -> null
            is String -> v
            else -> invalid("$path.$name is not a string or null")
        }
        fun bool(name: String): Boolean = raw(name) as? Boolean ?: invalid("$path.$name is not a boolean")
        fun long(name: String, min: Long = 0): Long {
            val v = raw(name) as? Long ?: invalid("$path.$name is not an integer")
            if (v < min) invalid("$path.$name is negative")
            return v
        }
        fun obj(name: String): Obj = Obj(raw(name) as? Map<*, *> ?: invalid("$path.$name is not an object"), "$path.$name")
        fun nullableObj(name: String): Obj? = when (val v = raw(name)) {
            null -> null
            is Map<*, *> -> Obj(v, "$path.$name")
            else -> invalid("$path.$name is not an object or null")
        }
        fun array(name: String): List<Any?> = raw(name) as? List<Any?> ?: invalid("$path.$name is not an array")
        inline fun <reified E : Enum<E>> enum(name: String): E =
            enumValue(string(name), "$path.$name")
    }
}
