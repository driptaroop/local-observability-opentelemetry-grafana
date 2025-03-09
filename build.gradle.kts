import org.jetbrains.gradle.ext.Application
import org.jetbrains.gradle.ext.runConfigurations
import org.jetbrains.gradle.ext.settings

plugins{
    id("org.jetbrains.gradle.plugin.idea-ext") version "1.1.10"
}

idea.project.settings {
    runConfigurations {
        create("run user", Application::class.java){
            mainClass = "org.dripto.application.service.user.AppKt"
            moduleName = "local-observability-opentelemetry-grafana.user-service.main"
            includeProvidedDependencies = true
            envs = mapOf(
                "JAVA_TOOL_OPTIONS" to "-javaagent:$rootDir/opentelemetry-javaagent.jar",
                "OTEL_SERVICE_NAME" to "user-service"
            )
        }
    }
}