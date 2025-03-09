package org.dripto.application.service.transactions

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.math.BigDecimal
import java.time.LocalDate
import java.util.UUID

@Entity
@Table(name = "transactions")
class Transaction (
    @Id
    @Column(name = "transaction_id")
    val transactionId: UUID,
    @Column(name = "transaction_date")
    val transactionDate: LocalDate,
    @Column(name = "transaction_amount")
    val transactionAmount: BigDecimal,
    @Column(name = "transaction_type")
    val transactionType: String,
    @Column(name = "merchant_name")
    val merchantName: String,
    @Column(name = "transaction_description")
    val transactionDescription: String,
    @Column(name = "transaction_category")
    val transactionCategory: String,
    @Column(name = "transaction_user")
    val transactionUser: UUID,
    @Column(name = "transaction_account")
    val transactionAccount: UUID
)

interface TransactionRepository: JpaRepository<Transaction, UUID>