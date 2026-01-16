package no.nav.tpt

import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.plugins.swagger.swaggerUI
import io.ktor.server.request.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.LocalDevDependenciesPlugin
import no.nav.tpt.plugins.configureAuthentication
import no.nav.tpt.plugins.configureKafka
import no.nav.tpt.plugins.dependencies
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.healthRoutes
import no.nav.tpt.routes.vulnRoutes
import org.slf4j.event.Level

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::localDevModule)
        .start(wait = true)
}

fun Application.localDevModule() {
    install(LocalDevDependenciesPlugin)

    install(CallLogging) {
        level = Level.INFO
        filter { call ->
            !call.request.uri.startsWith("/isalive") && !call.request.uri.startsWith("/isready")
        }
        format { call ->
            val status = call.response.status()
            val httpMethod = call.request.httpMethod.value
            val uri = call.request.uri
            val authorization = if (call.request.headers["Authorization"] != null) "[present]" else "[absent]"
            "$httpMethod $uri -> $status | Auth: $authorization"
        }
    }

    install(ServerContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
        })
    }

    configureAuthentication(dependencies.tokenIntrospectionService)

    routing {
        swaggerUI(path = "swagger", swaggerFile = "openapi.yaml")
        healthRoutes()
        configRoutes()
        vulnRoutes()
    }

    log.info("=".repeat(80))
    log.info("Local Development Mode Started")
    log.info("=".repeat(80))
    log.info("Server: http://0.0.0.0:8080")
    log.info("User: lokal.utvikler@nav.no (NAVident: Z999999)")
    log.info("Authentication: Any Bearer token accepted")
    log.info("Mock Data: src/test/resources/mock-vulnerabilities.json")
    log.info("=".repeat(80))
}

