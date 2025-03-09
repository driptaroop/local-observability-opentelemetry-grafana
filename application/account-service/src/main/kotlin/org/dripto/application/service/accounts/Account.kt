package org.dripto.application.service.accounts

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.math.BigDecimal
import java.time.LocalDate
import java.util.UUID

@Entity
@Table(name = "accounts")
data class Account(
    @Id
    @Column(name = "account_id")
    val accountId: UUID,
    @Column(name = "account_number")
    val accountNumber: String,
    @Column(name = "account_holder_name")
    val accountHolderName: String,
    val balance: BigDecimal,
    @Column(name = "account_type")
    val accountType: String,
    @Column(name = "interest_rate")
    val interestRate: BigDecimal,
    @Column(name = "account_open_date")
    val accountOpenDate: LocalDate,
    @Column(name = "account_status")
    val accountStatus: String,
    @Column(name = "user_id")
    val userId: UUID
)

interface AccountRepository: JpaRepository<Account, UUID> {
    fun findByUserId(userId: UUID): List<Account>?
    fun findByAccountNumber(accountNumber: String): Account?
}