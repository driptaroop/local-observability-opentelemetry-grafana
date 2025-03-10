--liquibase formatted sql

--changeset author:dripto
create table if not exists transactions
(
    transaction_id          UUID primary key,
    transaction_date        DATE,
    transaction_amount      DECIMAL(20, 2),
    transaction_type        VARCHAR(10),
    merchant_name           VARCHAR(50),
    transaction_description TEXT,
    transaction_category    VARCHAR(14),
    transaction_user        UUID,
    transaction_account     UUID
);

--rollback DROP TABLE transactions;