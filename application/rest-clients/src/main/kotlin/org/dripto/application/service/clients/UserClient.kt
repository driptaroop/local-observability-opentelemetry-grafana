package org.dripto.application.service.clients

import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.service.annotation.GetExchange
import org.springframework.web.service.annotation.HttpExchange
import java.time.LocalDateTime
import java.util.UUID

@HttpExchange
interface UserClient {
    @GetExchange("/users")
    fun getUsers(): List<User>

    @GetExchange("/users/{id}")
    fun getUserById(@PathVariable id: UUID): User

    class User(
        val id: UUID,
        val username: String,
        val firstName: String,
        val lastName: String,
        val email: String,
        val createdAt: LocalDateTime
    )
}