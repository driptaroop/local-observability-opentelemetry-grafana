package org.dripto.application.service.clients


import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.service.annotation.GetExchange
import org.springframework.web.service.annotation.HttpExchange
import org.springframework.web.service.annotation.PostExchange
import java.math.BigDecimal
import java.time.LocalDate
import java.util.UUID

@HttpExchange
interface AccountsClient {
    @GetExchange("/accounts")
    fun getAllAccounts(): List<Account>

    @GetExchange("/accounts/{accountId}")
    fun getAccount(@PathVariable("accountId") accountId: UUID): Account

    @GetExchange("/accounts/user/{userId}")
    fun getAccountsByUserId(@PathVariable("userId") userId: UUID): List<Account>?

    @GetExchange("/accounts/accounts/{accountNumber}")
    fun getAccountByAccountNumber(@PathVariable("accountNumber") accountNumber: String): Account?

    @PostExchange("/accounts/{accountId}/balance/{accountBalance}")
    fun updateAccountBalance(@PathVariable accountId: UUID, @PathVariable accountBalance: BigDecimal): Account

    data class Account(
        val accountId: UUID,
        val accountNumber: String,
        val accountHolderName: String,
        val balance: BigDecimal,
        val accountType: String,
        val interestRate: BigDecimal,
        val accountOpenDate: LocalDate,
        val accountStatus: String,
        val userId: UUID
    )
}