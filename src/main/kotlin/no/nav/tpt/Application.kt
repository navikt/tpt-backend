package no.nav.tpt

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.auth.principal
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.swagger.swaggerUI
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.request.*
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.DependenciesPlugin
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.configureAuthentication
import no.nav.tpt.plugins.configureKafka
import no.nav.tpt.plugins.configureNvdSync
import no.nav.tpt.plugins.configureStatusPages
import no.nav.tpt.plugins.configureVulnerabilityDataSync
import no.nav.tpt.plugins.dependencies
import no.nav.tpt.routes.adminRoutes
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.healthRoutes
import no.nav.tpt.routes.vulnRoutes
import no.nav.tpt.routes.vulnerabilitySearchRoutes
import org.slf4j.event.Level
import kotlin.time.Duration.Companion.seconds

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

    install(RateLimit) {
        register(RateLimitName("vulnerabilities-refresh")) {
            rateLimiter(limit = 1, refillPeriod = 60.seconds)
            requestKey { call ->
                call.principal<TokenPrincipal>()?.preferredUsername ?: "anonymous"
            }
        }
    }

    configureAuthentication(dependencies.tokenIntrospectionService)
    configureStatusPages()
    configureNvdSync()
    configureVulnerabilityDataSync()
    configureKafka()

    routing {
        swaggerUI(path = "swagger", swaggerFile = "openapi.yaml")
        healthRoutes()
        configRoutes()
        vulnRoutes()
        vulnerabilitySearchRoutes()
        adminRoutes()
    }
}

