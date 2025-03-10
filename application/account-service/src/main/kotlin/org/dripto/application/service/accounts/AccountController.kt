package org.dripto.application.service.accounts

import org.dripto.application.service.utils.log
import org.springframework.data.repository.findByIdOrNull
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal
import java.math.RoundingMode
import java.util.UUID

@RestController
class AccountController(private val accountRepository: AccountRepository) {
    @GetMapping("/accounts")
    fun getAllAccounts(): List<Account> {
        log.info("Getting all accounts")
        return accountRepository.findAll().also {
            log.debug("Found ${it.size} accounts {}", it)
        }
    }

    @GetMapping("/accounts/{accountId}")
    fun getAccount(@PathVariable("accountId") accountId: UUID): Account {
        log.info("Getting account with id {}", accountId)
        return accountRepository.getReferenceById(accountId).also {
            log.debug("Found account {}", it)
        }
    }

    @GetMapping("/accounts/user/{userId}")
    fun getAccountsByUserId(@PathVariable("userId") userId: UUID): List<Account>? {
        log.info("Getting accounts for user {}", userId)
        return accountRepository.findByUserId(userId).also {
            log.debug("Found account {} for user {}", it, userId)
        }
    }

    @GetMapping("/accounts/accounts/{accountNumber}")
    fun getAccountByAccountNumber(@PathVariable("accountNumber") accountNumber: String): Account? {
        log.info("Getting account with number {}", accountNumber)
        return accountRepository.findByAccountNumber(accountNumber).also {
            log.debug("For account number {} found account {}", accountNumber, it)
        }
    }

    @PostMapping("/accounts/{accountId}/balance/{accountBalance}")
    @Transactional
    fun updateAccountBalance(@PathVariable accountId: UUID, @PathVariable accountBalance: BigDecimal): Account {
        log.info("Updating account {}", accountId)
        val account = checkNotNull(accountRepository.findByIdOrNull(accountId)) {
            "Account with id $accountId not found"
        }
        account.balance = accountBalance.setScale(2, RoundingMode.HALF_DOWN)
        return accountRepository.save(account).also {
            log.debug("Updated account {}", it)
        }
    }

}