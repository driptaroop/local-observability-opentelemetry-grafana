package org.dripto.application.service.transactions

import org.dripto.application.service.clients.AccountsClient
import org.dripto.application.service.clients.NotificationsClient
import org.dripto.application.service.clients.UserClient
import org.dripto.application.service.utils.log
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.math.RoundingMode
import java.time.LocalDate
import java.util.UUID
import kotlin.random.Random

@RestController
class TransactionController(
    private val transactionRepository: TransactionRepository,
    private val notificationsClient: NotificationsClient,
    private val userClient: UserClient,
    private val accountsClient: AccountsClient
) {

    @PostMapping("/transactions/random")
    @Transactional
    fun randomTransaction(): Transaction {
        log.info("generating random transaction")
        val user = userClient.getUsers().random()
        log.debug("random transactions for user {}", user)
        val account = accountsClient.getAccountsByUserId(user.id)?.random()
            ?: throw IllegalStateException("no account found for user ${user.id}")

        log.debug("account for user {} is {}", user.id, account)
        val transaction = Transaction(
            transactionId = UUID.randomUUID(),
            transactionDate = LocalDate.now(),
            transactionAmount = Random.nextDouble(0.0, account.balance.toDouble()).toBigDecimal().setScale(2, RoundingMode.HALF_DOWN),
            transactionType = listOf("credit", "debit").random(),
            merchantName = listOf("Amazon", "Flipkart", "Myntra", "Zomato").random(),
            transactionDescription = listOf("buying for family", "buying for myself", "buying for friends").random(),
            transactionCategory = listOf("shopping", "food", "clothes", "electronics").random(),
            transactionUser = user.id,
            transactionAccount = account.accountId
        )
        log.debug("generated transaction for user {} and account {} is {}", user.id, account.accountId, transaction)

        accountsClient.updateAccountBalance(account.accountId, account.balance - transaction.transactionAmount)
        log.debug("account balance reduced for account {}. new balance {}", account.accountId, account.balance)

        notificationsClient.createNotification(
            NotificationsClient.NotificationRequest(
                userId = user.id,
                message = "transaction of ${transaction.transactionAmount} done on ${transaction.transactionDate}",
                priority = listOf("high", "medium", "low").random(),
                sender = listOf("system", "user").random()
            )
        )
        log.debug("sent notifications")
        return transactionRepository.save(transaction).also {
            log.info("created transaction for user {} and account {}: {}", user.id, account.accountId, it)
        }
    }

    @GetMapping("/transactions")
    fun getAllTransactions(): List<Transaction> {
        log.info("getting all transactions")
        return transactionRepository.findAll().also {
            log.debug("found {} transactions", it.size)
        }
    }

    @PostMapping("/transactions")
    @Transactional
    fun createTransaction(transaction: Transaction): Transaction {
        log.info("creating transaction {}", transaction)
        // check if user exists
        checkNotNull(userClient.getUserById(transaction.transactionUser))

        // check account exists
        checkNotNull(accountsClient.getAccount(transaction.transactionAccount))

        // check if transaction amount is valid
        val account = accountsClient.getAccount(transaction.transactionAccount)
        check(transaction.transactionAmount > 0.0.toBigDecimal() && transaction.transactionAmount <= account.balance) {
            "transaction amount should be greater than 0 and less than or equal to account balance"
        }

        accountsClient.updateAccountBalance(account.accountId, account.balance - transaction.transactionAmount)
        log.debug("account balance reduced for account {}. new balance {}", account.accountId, account.balance)

        notificationsClient.createNotification(
            NotificationsClient.NotificationRequest(
                userId = transaction.transactionUser,
                message = "transaction of ${transaction.transactionAmount} done on ${transaction.transactionDate}",
                priority = listOf("high", "medium", "low").random(),
                sender = listOf("system", "user").random()
            )
        )
        log.debug("sent notifications")
        return transactionRepository.save(transaction).also {
            log.info("created transaction for user {} and account {}: {}", transaction.transactionUser, account.accountId, it)
        }
    }
}

