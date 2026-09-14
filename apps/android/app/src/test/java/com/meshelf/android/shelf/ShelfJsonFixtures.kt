package com.meshelf.android.shelf

/** Builds ABI-8 JSON exactly as the contract shows it, with optional omission of one member. */
object ShelfJsonFixtures {
    fun q(value: String) = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun obj(members: List<Pair<String, String>>, omit: String?) =
        members.filter { it.first != omit }.joinToString(",", "{", "}") { (k, v) -> "${q(k)}:$v" }

    fun card(
        offerId: String = "11111111-1111-1111-1111-111111111111",
        sourceDevice: String = "22222222-2222-2222-2222-222222222222",
        sourceDisplayName: String = "CEDAR",
        ownership: String = "RECEIVED",
        kind: String = "TEXT",
        displayName: String = "",
        preview: String = "hello",
        byteLength: Long = 5,
        shelfSequence: Long = 1,
        availability: String = "READY",
        actions: List<String> = listOf("COPY_TEXT"),
        activeOperation: String = "null",
        lastAttempt: String = "null",
        omit: String? = null,
    ): String = obj(
        listOf(
            "sourceDevice" to q(sourceDevice),
            "offerId" to q(offerId),
            "sourceDisplayName" to q(sourceDisplayName),
            "ownership" to q(ownership),
            "kind" to q(kind),
            "displayName" to q(displayName),
            "preview" to q(preview),
            "byteLength" to "$byteLength",
            "shelfSequence" to "$shelfSequence",
            "availability" to q(availability),
            "supportedActions" to actions.joinToString(",", "[", "]") { q(it) },
            "activeOperation" to activeOperation,
            "lastAttempt" to lastAttempt,
        ),
        omit,
    )

    fun attempt(code: String = "UNCERTAIN_NO_REPLAY", sequence: Long = 3, detail: String = "null") =
        """{"code":${q(code)},"attemptSequence":$sequence,"filesProcessed":1,"bytesProcessed":12,"detail":$detail}"""

    fun peer(deviceId: String, name: String, reachability: String, outcome: String) =
        """{"deviceId":${q(deviceId)},"displayName":${q(name)},"reachability":${q(reachability)},"outcome":${q(outcome)}}"""

    fun observation(trigger: String, vararg peers: String) =
        """{"trigger":${q(trigger)},"peers":${peers.joinToString(",", "[", "]")}}"""

    fun snapshot(
        cards: List<String> = emptyList(),
        schemaVersion: String = "2",
        ready: String = "true",
        completeness: String = "\"COMPLETE\"",
        localDisplayName: String = "\"EMBER\"",
        peerObservation: String = "null",
        omit: String? = null,
    ): String = obj(
        listOf(
            "schemaVersion" to schemaVersion,
            "ready" to ready,
            "completeness" to completeness,
            "localDisplayName" to localDisplayName,
            "cards" to cards.joinToString(",", "[", "]"),
            "peerObservation" to peerObservation,
        ),
        omit,
    )

    /** Distinct keys and newest-first sequences for [count] received text cards. */
    fun textCards(count: Int): List<String> = (1..count).map { i ->
        card(offerId = "offer-$i", shelfSequence = (count - i + 1).toLong())
    }
}
