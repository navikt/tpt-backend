package no.nav.tpt

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.swagger.swaggerUI
import io.ktor.server.sse.SSE
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.request.*
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics
import io.micrometer.core.instrument.binder.logging.LogbackMetrics
import io.micrometer.core.instrument.binder.system.ProcessorMetrics
import io.micrometer.core.instrument.binder.system.UptimeMetrics
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.DependenciesPlugin
import no.nav.tpt.plugins.configureAuthentication
import no.nav.tpt.plugins.configureKafka
import no.nav.tpt.plugins.configureGcveSync
import no.nav.tpt.plugins.configureSightingsSync
import no.nav.tpt.plugins.configureStatusPages
import no.nav.tpt.plugins.configureVulnerabilityDataSync
import no.nav.tpt.plugins.dependencies
import no.nav.tpt.routes.adminRoutes
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.naisRoutes
import no.nav.tpt.routes.sseRoutes
import no.nav.tpt.routes.gitHubVulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilitySearchRoutes
import org.slf4j.event.Level
import no.nav.tpt.metrics.TPTMetrics
import no.nav.tpt.routes.dataCollectorRoutes

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(DependenciesPlugin)
    install(SSE)

    install(CallLogging) {
        level = Level.INFO
        filter { call ->
            !call.request.uri.startsWith("/internal")
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

    install(MicrometerMetrics) {
        registry = TPTMetrics.registry
        meterBinders = listOf(
            LogbackMetrics(),
            JvmGcMetrics(),
            JvmMemoryMetrics(),
            JvmThreadMetrics(),
            ProcessorMetrics(),
            UptimeMetrics(),
        )
    }

    configureAuthentication(dependencies.tokenIntrospectionService)
    configureStatusPages()
    configureVulnerabilityDataSync()
    configureGcveSync()
    configureSightingsSync()
    configureKafka()

    routing {
        swaggerUI(path = "swagger", swaggerFile = "openapi.yaml")
        naisRoutes()
        configRoutes()
        vulnerabilityRoutes()
        gitHubVulnerabilityRoutes()
        vulnerabilitySearchRoutes()
        adminRoutes()
        sseRoutes(dependencies.sseEventBus)
        dataCollectorRoutes()
    }
}

