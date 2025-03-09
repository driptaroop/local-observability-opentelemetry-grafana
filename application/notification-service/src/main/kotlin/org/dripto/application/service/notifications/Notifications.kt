package org.dripto.application.service.notifications

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.LocalDateTime
import java.util.UUID

@Entity
@Table(name = "notifications")
class Notifications(
    @Id
    @Column(name = "notification_id")
    val notificationId: UUID,
    val email: String,
    val message: String,
    val timestamp: LocalDateTime,
    val priority: String,
    @Column(name = "sender_name")
    val senderName: String,
    val deliveryStatus: String
)

interface NotificationsRepository: JpaRepository<Notifications, UUID>