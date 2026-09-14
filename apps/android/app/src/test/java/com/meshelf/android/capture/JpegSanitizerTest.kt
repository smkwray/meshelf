package com.meshelf.android.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO

class JpegSanitizerTest {
    @Test fun removesGpsDeviceMetadataAndPreservesOrientationAndPixels() {
        val source = requireNotNull(javaClass.getResourceAsStream("/fixtures/gps-orientation-6.jpg")).readBytes()
        val before = JpegSanitizer.inspectBytes(source)
        assertEquals(6, before.orientation)
        assertTrue(before.hasGpsExif)
        assertTrue(before.hasXmp)
        assertTrue(before.hasIptc)
        assertTrue(before.hasComment)

        val output = JpegSanitizer.sanitizeBytesForTest(source)
        val after = JpegSanitizer.inspectBytes(output)
        assertEquals(before.width, after.width)
        assertEquals(before.height, after.height)
        assertEquals(6, after.orientation)
        assertFalse(after.hasGpsExif)
        assertFalse(after.hasXmp)
        assertFalse(after.hasIptc)
        assertFalse(after.hasComment)
        assertNotNull(ImageIO.read(ByteArrayInputStream(output)))
    }
}
