package org.dripto.application.service.user

import org.dripto.application.service.utils.log
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
class UserController (private val userRepository: UserRepository) {
    @GetMapping("/users")
    fun getUsers(): List<User> {
        log.info("Getting all users")
        return userRepository.findAll().also {
            log.debug("Found all users: {}", it)
        }
    }

    @GetMapping("/users/{id}")
    fun getUserById(@PathVariable id: UUID): User {
        log.info("Getting user by id: {}", id)
        return userRepository.getReferenceById(id).also {
            log.debug("Found user for id {}: {}", id, it)
        }
    }
}

