package org.dripto.application.service.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.web.SecurityFilterChain

@SpringBootApplication
class App {
    @Bean
    @Order(1)
    fun authServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain = http.with(OAuth2AuthorizationServerConfigurer.authorizationServer(), Customizer.withDefaults()).build()

    @Bean
    @Order(2)
    fun standardSecurityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http.authorizeHttpRequests {
            it.requestMatchers("/actuator/**").permitAll()
            it.anyRequest().authenticated()
        }
            .formLogin { it.disable() }
            .csrf { it.disable() }.build()
}

fun main(args: Array<String>) {
    runApplication<App>(*args)
}