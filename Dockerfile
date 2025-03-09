FROM eclipse-temurin:21-alpine AS builder

WORKDIR /app
COPY . .
RUN ls -altr
COPY ca.crt /usr/local/share/ca-certificates/all-ca-certs.crt

RUN chmod 644 /usr/local/share/ca-certificates/all-ca-certs.crt && update-ca-certificates
RUN keytool -importcert -trustcacerts -cacerts -file /usr/local/share/ca-certificates/all-ca-certs.crt -alias all-ca-certs -storepass changeit -noprompt

RUN ./gradlew build

FROM eclipse-temurin:21-alpine AS user-service

WORKDIR /app

EXPOSE 8080
COPY --from=builder /app/application/user-service/build/libs/*.jar /app.jar
COPY opentelemetry-javaagent.jar ./otel.jar

ENTRYPOINT ["java", "-javaagent:/app/otel.jar", "-jar", "/app.jar"]

FROM eclipse-temurin:21-alpine AS notification-service

WORKDIR /app

EXPOSE 8080
COPY --from=builder /app/application/notification-service/build/libs/*.jar /app.jar
COPY opentelemetry-javaagent.jar ./otel.jar

ENTRYPOINT ["java", "-javaagent:/app/otel.jar", "-jar", "/app.jar"]

FROM eclipse-temurin:21-alpine AS account-service

WORKDIR /app

EXPOSE 8080
COPY --from=builder /app/application/account-service/build/libs/*.jar /app.jar
COPY opentelemetry-javaagent.jar ./otel.jar

ENTRYPOINT ["java", "-javaagent:/app/otel.jar", "-jar", "/app.jar"]

FROM eclipse-temurin:21-alpine AS transaction-service

WORKDIR /app

EXPOSE 8080
COPY --from=builder /app/application/transaction-service/build/libs/*.jar /app.jar
COPY opentelemetry-javaagent.jar ./otel.jar

ENTRYPOINT ["java", "-javaagent:/app/otel.jar", "-jar", "/app.jar"]
