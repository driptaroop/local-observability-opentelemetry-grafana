package org.dripto.application.service.clients

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestClient
import org.springframework.web.client.support.RestClientAdapter
import org.springframework.web.service.invoker.HttpServiceProxyFactory
import org.springframework.web.service.invoker.createClient

@Configuration
class ClientConfig {
    @Bean
    fun accountsClient(): AccountsClient = createRestClient<AccountsClient>("http://account-service:8080")

    @Bean
    fun notificationClient(): NotificationsClient = createRestClient<NotificationsClient>("http://notification-service:8080")

    @Bean
    fun userClient(): UserClient = createRestClient<UserClient>("http://user-service:8080")
}

inline fun <reified T : Any> createRestClient(baseUrl: String): T {
    val restClient = RestClient.builder().baseUrl(baseUrl).build()
    val adapter = RestClientAdapter.create(restClient)
    val factory = HttpServiceProxyFactory.builderFor(adapter).build()

    return factory.createClient<T>()
}