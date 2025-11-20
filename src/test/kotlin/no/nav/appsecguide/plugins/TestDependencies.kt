package no.nav.appsecguide.plugins

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.auth.MockTokenIntrospectionService
import no.nav.appsecguide.infrastructure.auth.TokenIntrospectionService
import no.nav.appsecguide.infrastructure.config.AppConfig
import no.nav.appsecguide.infrastructure.nais.MockNaisApiService
import no.nav.appsecguide.infrastructure.nais.NaisApiService
import no.nav.appsecguide.routes.healthRoutes
import no.nav.appsecguide.routes.naisRoutes
import no.nav.appsecguide.routes.userRoutes

fun Application.installTestDependencies(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    httpClient: HttpClient? = null
) {
    val client = httpClient ?: HttpClient(MockEngine) {
        engine {
            addHandler { request ->
                error("Unexpected HTTP request in test: ${request.url}")
            }
        }
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }
    }

    val testConfig = AppConfig(
        naisTokenIntrospectionEndpoint = "http://test-introspection",
        naisApiUrl = "http://test-nais-api",
        naisApiToken = "test-token",
        valkeyHost = "localhost",
        valkeyPort = 6379,
        valkeyUsername = "test",
        valkeyPassword = "test",
        cacheTtlMinutes = 1
    )

    val dependencies = Dependencies(
        config = testConfig,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        httpClient = client
    )

    attributes.put(DependenciesKey, dependencies)
}

fun Application.testModule(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService()
) {
    installTestDependencies(tokenIntrospectionService, naisApiService)

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

