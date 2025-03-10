rootProject.name = "local-observability-opentelemetry-grafana"

include(
    "account-service",
    "notification-service",
    "transaction-service",
    "user-service",
    "shared",
    "auth-server"
)

project(":account-service").projectDir = file("application/account-service")
project(":user-service").projectDir = file("application/user-service")
project(":transaction-service").projectDir = file("application/transaction-service")
project(":notification-service").projectDir = file("application/notification-service")
project(":shared").projectDir = file("application/shared")
project(":auth-server").projectDir = file("application/auth-server")