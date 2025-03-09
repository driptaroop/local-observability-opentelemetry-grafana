package org.dripto.application.service.user

import com.fasterxml.jackson.datatype.hibernate6.Hibernate6Module
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean

@SpringBootApplication
class App {
    @Bean
    fun hibernate6Module() = Hibernate6Module()
}

fun main(args: Array<String>) {
    runApplication<App>(*args)
}