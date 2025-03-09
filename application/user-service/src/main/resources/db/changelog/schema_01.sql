--liquibase formatted sql

--changeset author:dripto
CREATE TABLE if not exists user_data
(
    id           UUID PRIMARY KEY,
    username     TEXT NOT NULL,
    first_name   TEXT NOT NULL,
    last_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--rollback DROP TABLE user;