--liquibase formatted sql

--changeset author:dripto
create table if not exists notifications
(
    notification_id UUID primary key,
    email           text,
    message         TEXT,
    timestamp       timestamp,
    priority        VARCHAR(6),
    sender_name     TEXT,
    delivery_status VARCHAR(9)
);

--rollback DROP TABLE notifications;