package com.meshelf.android.shelf

import java.util.UUID

/**
 * A UI-generation fence, NOT the durable at-most-once journal. Native must durably
 * record authorization and platform-dispatch intent before invoking the platform.
 * Tokens are process-local, never persisted or trusted as remote authorization.
 */
class ForegroundGestureGate {
    data class Token internal constructor(val session: String, val generation: Long, val serial: Long)
    private val session = UUID.randomUUID().toString()
    private var generation = 0L
    private var serial = 0L
    private var resumed = false
    private var focused = false
    private var active: Token? = null

    @Synchronized fun setResumed(value: Boolean) {
        if (resumed != value) invalidate()
        resumed = value
    }
    @Synchronized fun setFocused(value: Boolean) {
        if (focused != value) invalidate()
        focused = value
    }
    @Synchronized fun issue(): Token? {
        if (!resumed || !focused) return null
        serial += 1
        return Token(session, generation, serial).also { active = it }
    }
    @Synchronized fun isCurrent(token: Token): Boolean =
        resumed && focused && token.session == session && active == token && token.generation == generation
    @Synchronized fun consume(token: Token): Boolean {
        if (!isCurrent(token)) return false
        active = null
        return true
    }
    @Synchronized fun invalidate() {
        generation += 1
        active = null
    }

    companion object {
        fun formatToken(token: Token): String = "${token.session}:${token.generation}:${token.serial}"

        fun parseToken(raw: String): Token? {
            val parts = raw.split(':')
            if (parts.size != 3) return null
            val generation = parts[1].toLongOrNull() ?: return null
            val serial = parts[2].toLongOrNull() ?: return null
            if (parts[0].isBlank()) return null
            return Token(parts[0], generation, serial)
        }
    }
}
