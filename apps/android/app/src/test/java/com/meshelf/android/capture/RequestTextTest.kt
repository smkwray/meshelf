package com.meshelf.android.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RequestTextTest {
    @Test fun markupRemainsLiteralPlainText() {
        assertEquals("<b>router label</b>", RequestText.requirePurpose("<b>router label</b>"))
    }

    @Test fun controlAndFormattingCharactersAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { RequestText.requirePurpose("line1\nline2") }
        assertThrows(IllegalArgumentException::class.java) { RequestText.requirePurpose("left\u202Eright") }
    }

    @Test fun requestIdsCannotEscapeDirectories() {
        assertThrows(IllegalArgumentException::class.java) { RequestText.requireRequestId("../escape") }
    }

    // The pairing id and transcript hash are echoed back to Rust and compared byte for byte, so any
    // spelling other than Rust's own lowercase hex could never match; refusing it early keeps the failure
    // here, visible, instead of an approval that silently binds to nothing.
    @Test fun pairingIdIsExactly32LowercaseHexCharacters() {
        val id = "0123456789abcdef0123456789abcdef"
        assertEquals(id, RequestText.requirePairingId(id))
        listOf(
            id.uppercase(),
            id.dropLast(1) + "F",
            id.dropLast(1),
            id + "0",
            "",
            "g" + id.drop(1),
            " " + id.drop(1),
        ).forEach { bad ->
            assertThrows(bad, IllegalArgumentException::class.java) { RequestText.requirePairingId(bad) }
        }
    }

    @Test fun transcriptHashIsExactly64LowercaseHexCharacters() {
        val hash = "0123456789abcdef".repeat(4)
        assertEquals(hash, RequestText.requireTranscriptHash(hash))
        listOf(
            hash.uppercase(),
            hash.dropLast(1) + "A",
            hash.dropLast(1),
            hash + "0",
            hash.take(32),
            "",
        ).forEach { bad ->
            assertThrows(bad, IllegalArgumentException::class.java) { RequestText.requireTranscriptHash(bad) }
        }
    }

    // The person compares digits by eye; other scripts' digits or a short code would make "the same
    // code" ambiguous across the two screens.
    @Test fun pairingCodeIsExactlySixAsciiDigits() {
        assertEquals("012345", RequestText.requirePairingCode("012345"))
        listOf("12345", "1234567", "12345a", "12 345", "+12345", "\u0661\u0662\u0663\u0664\u0665\u0666", "").forEach { bad ->
            assertThrows(bad, IllegalArgumentException::class.java) { RequestText.requirePairingCode(bad) }
        }
    }
}
