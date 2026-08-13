package no.nav.tpt

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.plugins.ratelimit.RateLimit
import io.ktor.server.plugins.ratelimit.RateLimitName
import io.ktor.server.plugins.swagger.swaggerUI
import io.ktor.server.request.httpMethod
import io.ktor.server.request.uri
import io.ktor.server.routing.routing
import kotlin.time.Duration.Companion.seconds
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.LocalDevDependenciesPlugin
import no.nav.tpt.plugins.configureAuthentication
import no.nav.tpt.plugins.dependencies
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.dataCollectorRoutes
import no.nav.tpt.routes.naisRoutes
import no.nav.tpt.routes.gitHubVulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilitySearchRoutes
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

    install(RateLimit) {
        register(RateLimitName("vulnerabilities-refresh")) {
            rateLimiter(limit = 1, refillPeriod = 60.seconds)
            requestKey { "local-dev" }
        }
    }

    configureAuthentication(dependencies.tokenIntrospectionService)

    routing {
        swaggerUI(path = "swagger", swaggerFile = "openapi.yaml")
        naisRoutes()
        configRoutes()
        vulnerabilitySearchRoutes()
        vulnerabilityRoutes()
        gitHubVulnerabilityRoutes()
        dataCollectorRoutes()
    }

    log.info("=".repeat(80))
    log.info("Local Development Mode Started")
    log.info("=".repeat(80))
    log.info("Server: http://0.0.0.0:8080")
    log.info("Swagger UI: http://0.0.0.0:8080/swagger")
    log.info("User: lokal.utvikler@nav.no (NAVident: Z999999)")
    log.info("Authentication: Any Bearer token accepted")
    log.info("=".repeat(80))
}

