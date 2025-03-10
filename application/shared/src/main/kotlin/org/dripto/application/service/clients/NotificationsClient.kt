package org.dripto.application.service.clients

import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.service.annotation.HttpExchange
import org.springframework.web.service.annotation.PostExchange
import java.time.LocalDateTime
import java.util.UUID


@HttpExchange
interface NotificationsClient{
    @PostExchange("/notifications")
    fun createNotification(@RequestBody notification: NotificationRequest)

    data class NotificationRequest(
        val userId: UUID,
        val message: String,
        val priority: String,
        val sender: String
    )
}