--liquibase formatted sql

--changeset author:dripto
create table accounts
(
    account_id          UUID primary key,
    account_number      VARCHAR(50),
    account_holder_name VARCHAR(50),
    balance             DECIMAL(9, 2),
    account_type        VARCHAR(10),
    interest_rate       DECIMAL(4, 2),
    account_open_date   DATE,
    account_status      VARCHAR(6),
    user_id             UUID
);
--rollback DROP TABLE accounts;