package org.dripto.application.service.transactions

import com.fasterxml.jackson.datatype.hibernate6.Hibernate6Module
import org.dripto.application.service.clients.ClientConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import

@SpringBootApplication
@Import(ClientConfig::class)
class App{
    @Bean
    fun hibernate6Module() = Hibernate6Module()
}

fun main(args: Array<String>) {
    runApplication<App>(*args)
}