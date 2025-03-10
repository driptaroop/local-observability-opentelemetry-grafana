package org.dripto.application.service.notifications

import com.fasterxml.jackson.datatype.hibernate6.Hibernate6Module
import org.dripto.application.service.clients.ClientConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@SpringBootApplication
@Import(ClientConfig::class)
class App{
    @Bean
    fun hibernate6Module() = Hibernate6Module()

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http.authorizeHttpRequests {
            it.requestMatchers("/actuator/**").permitAll()
            it.anyRequest().authenticated()
        }
            .oauth2ResourceServer { it.jwt(Customizer.withDefaults()) }
            .build()
}

fun main(args: Array<String>) {
    runApplication<App>(*args)
}