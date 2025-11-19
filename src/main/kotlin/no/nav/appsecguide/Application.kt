package no.nav.appsecguide

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.request.*
import kotlinx.serialization.json.Json
import no.nav.appsecguide.plugins.DependenciesPlugin
import no.nav.appsecguide.plugins.configureAuthentication
import no.nav.appsecguide.plugins.dependencies
import no.nav.appsecguide.routes.healthRoutes
import no.nav.appsecguide.routes.naisRoutes
import no.nav.appsecguide.routes.userRoutes
import org.slf4j.event.Level

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(DependenciesPlugin)

    install(CallLogging) {
        level = Level.INFO
        format { call ->
            val status = call.response.status()
            val httpMethod = call.request.httpMethod.value
            val uri = call.request.uri
            val userAgent = call.request.headers["User-Agent"]
            "$httpMethod $uri -> $status (User-Agent: $userAgent)"
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
        healthRoutes()
        userRoutes()
        naisRoutes()
    }
}

