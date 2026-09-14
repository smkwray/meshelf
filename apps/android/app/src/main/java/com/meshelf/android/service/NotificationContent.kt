package com.meshelf.android.service

import com.meshelf.android.capture.CaptureRequest
import com.meshelf.android.capture.RequestText

/** Plain-string notification content; no HTML/markup parsing is used. */
object NotificationContent {
    data class Content(
        val title: String,
        val text: String,
        val bigText: String,
    )

    fun available(deviceName: String, detail: String): Content {
        val name = RequestText.requireDeviceName(deviceName)
        val safeDetail = requireStatusDetail(detail)
        return Content(
            title = "meshelf capture availability",
            text = safeDetail,
            bigText = "$name — $safeDetail",
        )
    }

    fun request(request: CaptureRequest): Content = Content(
        title = "Photo requested by ${request.requesterName}",
        text = request.purpose,
        bigText = "Requested by ${request.requesterName}\nPurpose: ${request.purpose}",
    )

    fun delivered(requesterName: String): Content {
        val requester = RequestText.requireRequesterName(requesterName)
        return Content(
            title = "Photo delivered",
            text = "The temporary capture for $requester was removed.",
            bigText = "The photo was delivered to $requester and its temporary phone copy was removed.",
        )
    }

    private fun requireStatusDetail(value: String): String {
        require(value.isNotBlank()) { "notification status must not be blank" }
        require(value.toByteArray(Charsets.UTF_8).size <= 512) { "notification status is too long" }
        require(value.none(Character::isISOControl)) { "notification status contains a control character" }
        return value
    }
}
