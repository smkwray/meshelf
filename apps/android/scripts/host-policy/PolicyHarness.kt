import com.meshelf.android.capture.CaptureFiles
import com.meshelf.android.capture.CaptureRequest
import com.meshelf.android.capture.JpegSanitizer
import com.meshelf.android.capture.RequestText
import com.meshelf.android.service.NotificationContent
import com.meshelf.android.tailscale.TailscaleRouteSelector
import java.io.File
import java.nio.file.Files
import javax.imageio.ImageIO

private fun expectFailure(block: () -> Unit) {
    check(runCatching(block).isFailure) { "expected failure" }
}

fun main(args: Array<String>) {
    check(args.size == 1) { "fixture path required" }
    check(RequestText.requirePurpose("<b>literal</b>") == "<b>literal</b>")
    expectFailure { RequestText.requirePurpose("line1\nline2") }
    expectFailure { RequestText.requirePurpose("left\u202Eright") }
    expectFailure { RequestText.requireRequestId("../escape") }

    check(TailscaleRouteSelector.selectCgnatIpv4(listOf("10.0.0.1", "100.64.1.40")).getOrThrow() == "100.64.1.40")
    check(TailscaleRouteSelector.selectCgnatIpv4(listOf("10.0.0.1")).isFailure)
    check(TailscaleRouteSelector.selectCgnatIpv4(listOf("100.64.0.1", "100.65.0.1")).isFailure)

    val request = CaptureRequest("request-1", "CEDAR", "<b>router label</b>", 1_000L)
    val content = NotificationContent.request(request)
    check(content.text == "<b>router label</b>")

    val input = File(args[0]).readBytes()
    val before = JpegSanitizer.inspectBytes(input)
    check(before.orientation == 6 && before.hasGpsExif && before.hasXmp && before.hasIptc && before.hasComment)
    val sanitized = JpegSanitizer.sanitizeBytesForTest(input)
    val after = JpegSanitizer.inspectBytes(sanitized)
    check(after.orientation == 6)
    check(!after.hasGpsExif && !after.hasXmp && !after.hasIptc && !after.hasComment)
    check(after.width == before.width && after.height == before.height)
    check(ImageIO.read(sanitized.inputStream()) != null)

    val cache = Files.createTempDirectory("meshelf-policy-sweep").toFile()
    try {
        val now = 1_200_000L
        val old = CaptureFiles.prepareRequestDirectory(cache, "old")
        val fresh = CaptureFiles.prepareRequestDirectory(cache, "fresh")
        old.resolve("capture.jpg").writeText("old")
        fresh.resolve("capture.jpg").writeText("fresh")
        old.resolve("capture.jpg").setLastModified(1L)
        old.setLastModified(1L)
        fresh.resolve("capture.jpg").setLastModified(now - 1_000L)
        fresh.setLastModified(now - 1_000L)
        val result = CaptureFiles.sweepOlderThan(cache, now)
        check(result.removedRequestDirectories == 1 && result.retainedRequestDirectories == 1)
        check(!old.exists() && fresh.exists())
    } finally {
        cache.deleteRecursively()
    }

    println("PASS: purpose sanitization, CGNAT-only selection, literal notification content, JPEG metadata stripping/orientation, and ten-minute sweep")
}
