package com.meshelf.android.shelf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Moving between in-app Activities must not stop the resident, and a platform callback must only
 * reach the Activity in the foreground; with none, the backend reports FOREGROUND_LOST.
 */
class ForegroundOwnersTest {
    private val shelf = Any()
    private val put = Any()
    private val settings = Any()

    @Test fun forwardNavigationNeverClosesTheSession() {
        val owners = ForegroundOwners<String>()
        assertTrue("first start opens the session", owners.start(shelf, "shelf"))
        owners.resume(shelf)
        // Android order: A.onPause, B.onStart, B.onResume, A.onStop.
        owners.pause(shelf)
        assertFalse(owners.start(put, "put"))
        owners.resume(put)
        assertFalse("stopping the previous Activity must not close", owners.stop(shelf))
        assertEquals(1, owners.count())
        assertEquals("put", owners.current())
    }

    @Test fun backNavigationReturnsCallbacksToTheShelf() {
        val owners = ForegroundOwners<String>()
        owners.start(shelf, "shelf"); owners.resume(shelf); owners.pause(shelf)
        owners.start(settings, "settings"); owners.resume(settings); owners.stop(shelf)
        owners.pause(settings)
        assertFalse(owners.start(shelf, "shelf"))
        owners.resume(shelf)
        assertFalse(owners.stop(settings))
        assertEquals("shelf", owners.current())
    }

    @Test fun pausedOwnerIsCurrentOnlyUntilAnotherStarts() {
        val owners = ForegroundOwners<String>()
        owners.start(shelf, "shelf"); owners.resume(shelf); owners.pause(shelf)
        assertEquals("a paused but started owner still receives callbacks (its gate refuses them)", "shelf", owners.current())
        owners.start(put, "put")
        assertEquals("put", owners.current())
    }

    @Test fun leavingTheAppClosesExactlyOnceAndDropsCallbacks() {
        val owners = ForegroundOwners<String>()
        owners.start(shelf, "shelf"); owners.resume(shelf); owners.pause(shelf)
        assertTrue(owners.stop(shelf))
        assertFalse("a second stop must not release the resident twice", owners.stop(shelf))
        assertNull(owners.current())
        assertEquals(0, owners.count())
        assertTrue("returning reopens the session", owners.start(shelf, "shelf"))
    }

    /**
     * Rotation, dark mode or font scale recreate the Activity with the old instance stopped first.
     * Releasing there stopped the resident in the gap and made the replacement look like a fresh
     * open, so every rotation ran a catalog round to every peer.
     */
    @Test fun configurationChangeKeepsTheSessionOpenWithoutReopening() {
        val owners = ForegroundOwners<String>()
        val replacement = Any()
        assertTrue(owners.start(shelf, "shelf"))
        owners.resume(shelf)
        // Android order: old.onPause, old.onStop, old.onDestroy, new.onCreate, new.onStart.
        owners.pause(shelf)
        owners.stopForRecreate(shelf)
        assertEquals("the resident stays owned across the gap", 1, owners.count())
        assertNull("a destroyed instance must never receive a platform callback", owners.current())
        assertFalse("the replacement must not reopen the session", owners.start(replacement, "replacement"))
        owners.resume(replacement)
        assertEquals(1, owners.count())
        assertEquals("replacement", owners.current())
        assertFalse("the parked instance was already released", owners.stop(shelf))
        assertTrue("leaving afterwards still closes exactly once", owners.stop(replacement))
    }

    @Test fun unknownOwnersCannotResumeOrClose() {
        val owners = ForegroundOwners<String>()
        owners.start(shelf, "shelf")
        owners.resume(put)
        assertFalse(owners.stop(put))
        assertEquals("shelf", owners.current())
    }
}
