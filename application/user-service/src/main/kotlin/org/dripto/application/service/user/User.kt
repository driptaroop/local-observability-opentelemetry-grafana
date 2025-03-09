package org.dripto.application.service.user

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import java.time.LocalDateTime
import java.util.UUID

@Entity
@Table(name = "user_data")
class User(
    @Id
    val id: UUID,
    val username: String,
    @Column(name = "first_name")
    val firstName: String,
    @Column(name = "last_name")
    val lastName: String,
    val email: String,
    @Column(name = "created_at")
    val createdAt: LocalDateTime
)

interface UserRepository: JpaRepository<User, UUID> {
    @Query("SELECT u FROM User u WHERE u.username = :username")
    fun getByUsername(username: String): User?
}