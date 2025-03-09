package org.dripto.application.service.transactions

import org.dripto.application.service.clients.AccountsClient
import org.dripto.application.service.clients.NotificationsClient
import org.dripto.application.service.clients.UserClient
import org.dripto.application.service.utils.log
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDate
import java.util.UUID

@RestController
class TransactionController(
    private val transactionRepository: TransactionRepository,
    private val notificationsClient: NotificationsClient,
    private val userClient: UserClient,
    private val accountsClient: AccountsClient
) {

    @PostMapping("/transactions/random")
    @Transactional
    fun randomTransaction() {
        log.info("generating random transaction")
        val user = userClient.getUsers().random()
        log.debug("random transactions for user {}", user)
        val account = accountsClient.getAccountsByUserId(user.id)?.random()
            ?: throw IllegalStateException("no account found for user ${user.id}")
        log.debug("account for user {} is {}", user.id, account)
        val transaction = Transaction(
            transactionId = UUID.randomUUID(),
            transactionDate = LocalDate.now(),
            transactionAmount = "${(1..1000).random()}.${(1..100).random()}".toBigDecimal(),
            transactionType = listOf("credit", "debit").random(),
            merchantName = listOf("Amazon", "Flipkart", "Myntra", "Zomato").random(),
            transactionDescription = listOf("buying for family", "buying for myself", "buying for friends").random(),
            transactionCategory = listOf("shopping", "food", "clothes", "electronics").random(),
            transactionUser = user.id,
            transactionAccount = account.accountId
        )
        log.debug("generated transaction for user {} and account {} is {}", user.id, account.accountId, transaction)
        notificationsClient.createNotification(
            NotificationsClient.NotificationRequest(
                userId = user.id,
                message = "transaction of ${transaction.transactionAmount} done on ${transaction.transactionDate}",
                priority = listOf("high", "medium", "low").random(),
                sender = listOf("system", "user").random()
            )
        )
        log.debug("sent notifications")
        transactionRepository.save(transaction).also {
            log.info("created transaction for user {} and account {}: {}", user.id, account.accountId, it)
        }
    }
}

