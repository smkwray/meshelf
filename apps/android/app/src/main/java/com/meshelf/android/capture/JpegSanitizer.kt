package com.meshelf.android.capture

import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * Rebuilds a CameraX JPEG without copying source APP/COM metadata segments.
 * The encoded image scan is not transcoded. A minimal EXIF block containing
 * only the original orientation value is emitted; GPS, XMP, IPTC, comments,
 * maker/model/serial fields, thumbnails, and unknown application segments are dropped.
 */
object JpegSanitizer {
    const val MAX_JPEG_BYTES: Int = 64 * 1024 * 1024

    data class Inspection(
        val width: Int,
        val height: Int,
        val orientation: Int,
        val hasGpsExif: Boolean,
        val hasXmp: Boolean,
        val hasIptc: Boolean,
        val hasComment: Boolean,
    )

    data class SanitizedJpeg(
        val width: Int,
        val height: Int,
        val orientation: Int,
        val byteLength: Long,
        val sha256: String,
    )

    private data class ParsedJpeg(
        val inspection: Inspection,
        val structuralHeaderRanges: List<IntRange>,
        val firstScanStart: Int,
        val endExclusive: Int,
    )

    fun inspect(file: File): Inspection = inspectBytes(readBounded(file))

    fun inspectBytes(bytes: ByteArray): Inspection = parse(bytes).inspection

    fun sanitize(source: File, destination: File): SanitizedJpeg {
        require(source.isFile) { "source JPEG is unavailable" }
        require(!destination.exists()) { "sanitized destination already exists" }
        val input = readBounded(source)
        val parsed = parse(input)
        val output = rebuild(input, parsed)
        val verified = parse(output).inspection
        require(!verified.hasGpsExif && !verified.hasXmp && !verified.hasIptc && !verified.hasComment) {
            "sanitized JPEG retained forbidden metadata"
        }
        require(verified.orientation == parsed.inspection.orientation) { "orientation was not preserved" }
        require(verified.width == parsed.inspection.width && verified.height == parsed.inspection.height) {
            "image dimensions changed during metadata stripping"
        }

        destination.parentFile?.let { parent ->
            require(parent.mkdirs() || parent.isDirectory) { "could not create destination directory" }
        }
        val temporary = File(destination.parentFile, ".${destination.name}.sanitizing-${System.nanoTime()}")
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(output)
                stream.fd.sync()
            }
            try {
                Files.move(temporary.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), destination.toPath())
            }
        } finally {
            if (temporary.exists()) temporary.delete()
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(output).toHex()
        return SanitizedJpeg(
            width = verified.width,
            height = verified.height,
            orientation = verified.orientation,
            byteLength = output.size.toLong(),
            sha256 = digest,
        )
    }

    fun sanitizeBytesForTest(bytes: ByteArray): ByteArray {
        require(bytes.size <= MAX_JPEG_BYTES) { "JPEG exceeds bound" }
        return rebuild(bytes, parse(bytes))
    }

    private fun readBounded(file: File): ByteArray {
        val length = file.length()
        require(length in 4..MAX_JPEG_BYTES.toLong()) { "JPEG size is outside the allowed bound" }
        return file.readBytes().also { bytes ->
            require(bytes.size.toLong() == length) { "JPEG changed while it was read" }
        }
    }

    private fun rebuild(input: ByteArray, parsed: ParsedJpeg): ByteArray {
        val orientationSegment = minimalOrientationExif(parsed.inspection.orientation)
        val estimated = 2 + orientationSegment.size +
            parsed.structuralHeaderRanges.sumOf { it.last - it.first + 1 } +
            (parsed.endExclusive - parsed.firstScanStart)
        val output = ByteArray(estimated)
        var cursor = 0

        output[cursor++] = 0xff.toByte()
        output[cursor++] = 0xd8.toByte()
        orientationSegment.copyInto(output, cursor)
        cursor += orientationSegment.size

        parsed.structuralHeaderRanges.forEach { range ->
            input.copyInto(output, cursor, range.first, range.last + 1)
            cursor += range.last - range.first + 1
        }
        input.copyInto(output, cursor, parsed.firstScanStart, parsed.endExclusive)
        cursor += parsed.endExclusive - parsed.firstScanStart
        require(cursor == output.size) { "internal JPEG reconstruction length mismatch" }
        return output
    }

    private fun parse(bytes: ByteArray): ParsedJpeg {
        require(bytes.size in 4..MAX_JPEG_BYTES) { "JPEG size is outside the allowed bound" }
        require(u8(bytes[0]) == 0xff && u8(bytes[1]) == 0xd8) { "missing JPEG SOI" }

        var index = 2
        var width: Int? = null
        var height: Int? = null
        var orientation = 1
        var hasGps = false
        var hasXmp = false
        var hasIptc = false
        var hasComment = false
        val structuralRanges = mutableListOf<IntRange>()
        var scanStart = -1
        var scanDataStart = -1

        while (index < bytes.size) {
            val markerStart = index
            require(u8(bytes[index]) == 0xff) { "expected JPEG marker at offset $index" }
            while (index < bytes.size && u8(bytes[index]) == 0xff) index += 1
            require(index < bytes.size) { "truncated JPEG marker" }
            val marker = u8(bytes[index++])
            require(marker != 0x00) { "unexpected stuffed byte before image scan" }
            require(marker != 0xd8) { "unexpected nested JPEG SOI" }
            require(marker != 0xd9) { "JPEG ended before an image scan" }

            if (isStandalone(marker)) {
                structuralRanges += markerStart until index
                continue
            }

            require(index + 2 <= bytes.size) { "truncated JPEG segment length" }
            val segmentLength = be16(bytes, index)
            require(segmentLength >= 2) { "invalid JPEG segment length" }
            val payloadStart = index + 2
            val segmentEnd = index + segmentLength
            require(segmentEnd <= bytes.size) { "JPEG segment exceeds file" }

            when {
                marker == 0xe1 -> {
                    val exif = parseExif(bytes, payloadStart, segmentEnd)
                    if (exif != null) {
                        orientation = exif.first
                        hasGps = hasGps || exif.second
                    }
                    hasXmp = hasXmp || startsWithAscii(
                        bytes,
                        payloadStart,
                        segmentEnd,
                        "http://ns.adobe.com/xap/1.0/\u0000",
                    )
                }
                marker == 0xed -> hasIptc = true
                marker == 0xfe -> hasComment = true
                isStartOfFrame(marker) -> {
                    require(segmentLength >= 8) { "short JPEG frame header" }
                    val frameHeight = be16(bytes, payloadStart + 1)
                    val frameWidth = be16(bytes, payloadStart + 3)
                    require(frameWidth > 0 && frameHeight > 0) { "invalid JPEG dimensions" }
                    if (width != null || height != null) {
                        require(width == frameWidth && height == frameHeight) {
                            "conflicting JPEG frame dimensions"
                        }
                    }
                    width = frameWidth
                    height = frameHeight
                }
            }

            if (marker == 0xda) {
                scanStart = markerStart
                scanDataStart = segmentEnd
                break
            }

            if (!isApplicationMarker(marker) && marker != 0xfe) {
                structuralRanges += markerStart until segmentEnd
            }
            index = segmentEnd
        }

        require(scanStart >= 0 && scanDataStart >= 0) { "JPEG has no image scan" }
        val endExclusive = findEoiAndRejectPostScanMetadata(bytes, scanDataStart)
        return ParsedJpeg(
            inspection = Inspection(
                width = requireNotNull(width) { "JPEG has no frame dimensions" },
                height = requireNotNull(height) { "JPEG has no frame dimensions" },
                orientation = orientation,
                hasGpsExif = hasGps,
                hasXmp = hasXmp,
                hasIptc = hasIptc,
                hasComment = hasComment,
            ),
            structuralHeaderRanges = structuralRanges,
            firstScanStart = scanStart,
            endExclusive = endExclusive,
        )
    }

    private fun findEoiAndRejectPostScanMetadata(bytes: ByteArray, start: Int): Int {
        var index = start
        while (index < bytes.size) {
            if (u8(bytes[index]) != 0xff) {
                index += 1
                continue
            }

            var markerCodeIndex = index + 1
            while (markerCodeIndex < bytes.size && u8(bytes[markerCodeIndex]) == 0xff) {
                markerCodeIndex += 1
            }
            require(markerCodeIndex < bytes.size) { "truncated marker in JPEG scan" }
            val marker = u8(bytes[markerCodeIndex])

            when {
                marker == 0x00 -> index = markerCodeIndex + 1
                marker in 0xd0..0xd7 -> index = markerCodeIndex + 1
                marker == 0xd9 -> {
                    val end = markerCodeIndex + 1
                    require(bytes.copyOfRange(end, bytes.size).all { u8(it) == 0x00 || u8(it) == 0xff }) {
                        "non-padding data follows JPEG EOI"
                    }
                    return end
                }
                isApplicationMarker(marker) || marker == 0xfe ->
                    error("metadata marker appears after the first JPEG scan")
                isStandalone(marker) -> index = markerCodeIndex + 1
                else -> {
                    val lengthOffset = markerCodeIndex + 1
                    require(lengthOffset + 2 <= bytes.size) { "truncated post-scan segment length" }
                    val length = be16(bytes, lengthOffset)
                    require(length >= 2) { "invalid post-scan segment length" }
                    val end = lengthOffset + length
                    require(end <= bytes.size) { "post-scan segment exceeds file" }
                    index = end
                }
            }
        }
        error("JPEG is missing EOI")
    }

    private fun parseExif(bytes: ByteArray, start: Int, end: Int): Pair<Int, Boolean>? {
        val signature = byteArrayOf('E'.code.toByte(), 'x'.code.toByte(), 'i'.code.toByte(), 'f'.code.toByte(), 0, 0)
        if (end - start < signature.size || !bytes.copyOfRange(start, start + signature.size).contentEquals(signature)) {
            return null
        }

        val tiff = start + signature.size
        require(tiff + 8 <= end) { "truncated EXIF TIFF header" }
        val littleEndian = when (String(bytes, tiff, 2, Charsets.US_ASCII)) {
            "II" -> true
            "MM" -> false
            else -> error("invalid EXIF byte order")
        }
        require(read16(bytes, tiff + 2, littleEndian) == 42) { "invalid EXIF TIFF magic" }
        val ifdOffset = read32(bytes, tiff + 4, littleEndian)
        require(ifdOffset in 8..(end - tiff - 2)) { "invalid EXIF IFD offset" }
        val ifd = tiff + ifdOffset
        val count = read16(bytes, ifd, littleEndian)
        require(count <= 512) { "EXIF IFD entry count exceeds bound" }
        require(ifd + 2 + count * 12 + 4 <= end) { "truncated EXIF IFD" }

        var orientation = 1
        var hasGps = false
        repeat(count) { entryIndex ->
            val entry = ifd + 2 + entryIndex * 12
            val tag = read16(bytes, entry, littleEndian)
            val type = read16(bytes, entry + 2, littleEndian)
            val valueCount = read32(bytes, entry + 4, littleEndian)
            if (tag == 0x8825) hasGps = true
            if (tag == 0x0112 && type == 3 && valueCount == 1) {
                val candidate = read16(bytes, entry + 8, littleEndian)
                if (candidate in 1..8) orientation = candidate
            }
        }
        return orientation to hasGps
    }

    private fun minimalOrientationExif(orientation: Int): ByteArray {
        require(orientation in 1..8) { "invalid EXIF orientation" }
        val payload = byteArrayOf(
            'E'.code.toByte(), 'x'.code.toByte(), 'i'.code.toByte(), 'f'.code.toByte(), 0, 0,
            'M'.code.toByte(), 'M'.code.toByte(), 0, 42, 0, 0, 0, 8,
            0, 1,
            0x01, 0x12, 0, 3, 0, 0, 0, 1,
            0, orientation.toByte(), 0, 0,
            0, 0, 0, 0,
        )
        val length = payload.size + 2
        return byteArrayOf(
            0xff.toByte(),
            0xe1.toByte(),
            (length ushr 8).toByte(),
            length.toByte(),
            *payload,
        )
    }

    private fun startsWithAscii(
        bytes: ByteArray,
        start: Int,
        end: Int,
        value: String,
    ): Boolean {
        val expected = value.toByteArray(Charsets.US_ASCII)
        if (end - start < expected.size) return false
        return expected.indices.all { bytes[start + it] == expected[it] }
    }

    private fun isApplicationMarker(marker: Int): Boolean = marker in 0xe0..0xef

    private fun isStandalone(marker: Int): Boolean = marker == 0x01 || marker in 0xd0..0xd7

    private fun isStartOfFrame(marker: Int): Boolean =
        marker in 0xc0..0xcf && marker !in setOf(0xc4, 0xc8, 0xcc)

    private fun be16(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= bytes.size) { "integer read exceeds buffer" }
        return (u8(bytes[offset]) shl 8) or u8(bytes[offset + 1])
    }

    private fun read16(bytes: ByteArray, offset: Int, littleEndian: Boolean): Int {
        require(offset >= 0 && offset + 2 <= bytes.size) { "integer read exceeds buffer" }
        return if (littleEndian) {
            u8(bytes[offset]) or (u8(bytes[offset + 1]) shl 8)
        } else {
            (u8(bytes[offset]) shl 8) or u8(bytes[offset + 1])
        }
    }

    private fun read32(bytes: ByteArray, offset: Int, littleEndian: Boolean): Int {
        require(offset >= 0 && offset + 4 <= bytes.size) { "integer read exceeds buffer" }
        val value = if (littleEndian) {
            u8(bytes[offset]).toLong() or
                (u8(bytes[offset + 1]).toLong() shl 8) or
                (u8(bytes[offset + 2]).toLong() shl 16) or
                (u8(bytes[offset + 3]).toLong() shl 24)
        } else {
            (u8(bytes[offset]).toLong() shl 24) or
                (u8(bytes[offset + 1]).toLong() shl 16) or
                (u8(bytes[offset + 2]).toLong() shl 8) or
                u8(bytes[offset + 3]).toLong()
        }
        require(value <= Int.MAX_VALUE.toLong()) { "integer exceeds supported bound" }
        return value.toInt()
    }

    private fun u8(value: Byte): Int = value.toInt() and 0xff

    private fun ByteArray.toHex(): String = joinToString(separator = "") { "%02x".format(it) }
}
