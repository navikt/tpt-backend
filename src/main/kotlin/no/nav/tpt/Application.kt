package no.nav.tpt

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.swagger.swaggerUI
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.request.*
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.DependenciesPlugin
import no.nav.tpt.plugins.configureAuthentication
import no.nav.tpt.plugins.configureKafka
import no.nav.tpt.plugins.configureNvdSync
import no.nav.tpt.plugins.dependencies
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.healthRoutes
import no.nav.tpt.routes.vulnRoutes
import org.slf4j.event.Level

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(DependenciesPlugin)

    install(CallLogging) {
        level = Level.INFO
        filter { call ->
            !call.request.uri.startsWith("/isalive") && !call.request.uri.startsWith("/isready")
        }
        format { call ->
            val status = call.response.status()
            val httpMethod = call.request.httpMethod.value
            val uri = call.request.uri
            "$httpMethod $uri -> $status"
        }
    }

    install(ServerContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
        })
    }

    configureAuthentication(dependencies.tokenIntrospectionService)
    configureNvdSync()
    configureKafka()

    routing {
        swaggerUI(path = "swagger", swaggerFile = "openapi.yaml")
        healthRoutes()
        configRoutes()
        vulnRoutes()
    }
}

