package com.meshelf.android.shelf

import org.junit.Assert.assertEquals
import org.junit.Test

class ShelfContractTest {
    @Test fun productionModelAndForegroundFenceContracts() {
        assertEquals(23, runShelfContractChecks().size)
    }
}
