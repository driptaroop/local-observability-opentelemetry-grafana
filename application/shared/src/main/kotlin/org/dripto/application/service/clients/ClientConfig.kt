package org.dripto.application.service.clients

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor
import org.springframework.web.client.RestClient
import org.springframework.web.client.support.RestClientAdapter
import org.springframework.web.service.invoker.HttpServiceProxyFactory
import org.springframework.web.service.invoker.createClient

@Configuration
class ClientConfig(
    @Value("\${spring.application.name}") private val clientId: String
) {
    @Bean
    fun accountsClient(interceptor: OAuth2ClientHttpRequestInterceptor): AccountsClient = createRestClient<AccountsClient>("http://account-service:8080", interceptor)

    @Bean
    fun notificationClient(interceptor: OAuth2ClientHttpRequestInterceptor): NotificationsClient = createRestClient<NotificationsClient>("http://notification-service:8080", interceptor)

    @Bean
    fun userClient(interceptor: OAuth2ClientHttpRequestInterceptor): UserClient = createRestClient<UserClient>("http://user-service:8080", interceptor)

    @Bean
    fun oAuth2ClientHttpRequestInterceptor(manager: OAuth2AuthorizedClientManager): OAuth2ClientHttpRequestInterceptor {
        val interceptor = OAuth2ClientHttpRequestInterceptor(manager)
        interceptor.setClientRegistrationIdResolver { clientId }
        return interceptor
    }
}

inline fun <reified T : Any> createRestClient(baseUrl: String, interceptor: OAuth2ClientHttpRequestInterceptor): T {
    val restClient = RestClient.builder().baseUrl(baseUrl).requestInterceptor(interceptor).build()
    val adapter = RestClientAdapter.create(restClient)
    val factory = HttpServiceProxyFactory.builderFor(adapter).build()

    return factory.createClient<T>()
}

