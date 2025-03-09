rootProject.name = "local-observability-opentelemetry-grafana"

include(
    "account-service",
    "notification-service",
    "transaction-service",
    "user-service",
    "rest-clients"
)

project(":account-service").projectDir = file("application/account-service")
project(":user-service").projectDir = file("application/user-service")
project(":transaction-service").projectDir = file("application/transaction-service")
project(":notification-service").projectDir = file("application/notification-service")
project(":rest-clients").projectDir = file("application/rest-clients")