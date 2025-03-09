package org.dripto.application.service.notifications

import org.dripto.application.service.clients.UserClient
import org.dripto.application.service.utils.log
import org.springframework.http.HttpStatus
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDateTime
import java.util.UUID

@RestController
class NotificationsController(private val notificationsRepository: NotificationsRepository, private val userClient: UserClient) {
    @PostMapping("/notifications")
    @Transactional
    @ResponseStatus(HttpStatus.CREATED)
    fun createNotification(@RequestBody notificationRequest: NotificationRequest): UUID {
        log.info("creating notification for user: ${notificationRequest.userId}")
        log.debug("notification request: {}", notificationRequest)
        val user = userClient.getUserById(notificationRequest.userId)
        log.debug("user for notification: {}", user)
        val notification = Notifications(
            notificationId = UUID.randomUUID(),
            email = user.email,
            message = notificationRequest.message,
            timestamp = LocalDateTime.now(),
            priority = notificationRequest.priority,
            senderName = notificationRequest.sender,
            deliveryStatus = listOf("pending", "delivered", "failed").random()
        )
        notificationsRepository.save(notification)
        log.debug("notification created: {}", notification)
        return notification.notificationId
    }
}

data class NotificationRequest(
    val userId: UUID,
    val message: String,
    val priority: String,
    val sender: String
)