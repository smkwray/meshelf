package com.meshelf.android.shelf

/**
 * Reference-counted foreground ownership across in-app Activities. Android starts the next
 * Activity before stopping the previous one, so moving between Shelf, Put on shelf and Settings
 * never drops the count to zero and never stops the resident. A configuration change is the
 * exception Android orders the other way (old onStop before new onStart), so the old instance is
 * parked by [stopForRecreate] and released when its replacement starts. Platform callbacks go only
 * to [current]: the resumed owner, otherwise the most recently started live one, otherwise nobody.
 */
class ForegroundOwners<T> {
    private val started = LinkedHashMap<Any, T>()
    private val recreating = HashSet<Any>()
    private var resumed: Any? = null

    /**
     * Returns true when this start opened the foreground session (0 -> 1 owners). A start while an
     * owner is parked for recreation is its replacement: the session stays open, and the parked
     * instance is released here rather than by its own onStop.
     */
    @Synchronized
    fun start(owner: Any, value: T): Boolean {
        val opened = started.isEmpty()
        recreating.forEach { started.remove(it) }
        recreating.clear()
        started.remove(owner)
        started[owner] = value
        return opened
    }

    /** onStop during a configuration change: keep the session open until the replacement starts. */
    @Synchronized
    fun stopForRecreate(owner: Any) {
        if (!started.containsKey(owner)) return
        if (resumed === owner) resumed = null
        recreating += owner
    }

    @Synchronized
    fun resume(owner: Any) {
        if (started.containsKey(owner)) resumed = owner
    }

    @Synchronized
    fun pause(owner: Any) {
        if (resumed === owner) resumed = null
    }

    /** Returns true when this stop closed the foreground session (1 -> 0 owners). */
    @Synchronized
    fun stop(owner: Any): Boolean {
        if (started.remove(owner) == null) return false
        recreating.remove(owner)
        if (resumed === owner) resumed = null
        return started.isEmpty()
    }

    @Synchronized
    fun current(): T? = resumed?.let { started[it] } ?: started.entries.lastOrNull { it.key !in recreating }?.value

    @Synchronized
    fun count(): Int = started.size
}
