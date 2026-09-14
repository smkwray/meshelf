package com.meshelf.android.service

import com.meshelf.android.capture.CaptureRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationContentTest {
    @Test fun requestContentIncludesLiteralRequesterAndPurpose() {
        val content = NotificationContent.request(
            CaptureRequest("request-1", "CEDAR", "<b>Photograph router label</b>", 1000L),
        )
        assertEquals("Photo requested by CEDAR", content.title)
        assertEquals("<b>Photograph router label</b>", content.text)
        assertTrue(content.bigText.contains("Purpose: <b>Photograph router label</b>"))
    }
}
