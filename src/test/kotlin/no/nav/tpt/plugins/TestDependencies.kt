package no.nav.tpt.plugins

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.createMockCachedKevService
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.epss.MockEpssService
import no.nav.tpt.plugins.LeaderElection
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl
import no.nav.tpt.routes.healthRoutes
import no.nav.tpt.routes.vulnRoutes

fun Application.installTestDependencies(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    kevService: KevService = createMockCachedKevService(),
    epssService: EpssService = MockEpssService(),
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
        dbJdbcUrl = "jdbc:postgresql://localhost:5432/test_db?user=test&password=test",
        nvdApiKey = null,
        valkeyHost = "localhost",
        valkeyPort = 6379,
        valkeyUsername = "test",
        valkeyPassword = "test",
        cacheTtlMinutes = 1
    )

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()

    // Mock NVD services for tests (not using real database)
    val mockNvdRepository = no.nav.tpt.infrastructure.nvd.MockNvdRepository()
    val mockNvdSyncService = no.nav.tpt.infrastructure.nvd.MockNvdSyncService()

    val vulnService = VulnServiceImpl(naisApiService, kevService, epssService, mockNvdRepository, riskScorer)

    // Stub database for tests - creates a minimal database instance that won't actually be used
    // Real database tests use testcontainers in specific integration tests
    val stubDatabase = org.jetbrains.exposed.sql.Database.connect(
        url = "jdbc:postgresql://stub:5432/stub",
        driver = "org.postgresql.Driver",
        user = "stub",
        password = "stub"
    )

    // Mock leader election - always returns true in tests
    val mockLeaderElection = LeaderElection(client)

    val dependencies = Dependencies(
        config = testConfig,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        kevService = kevService,
        epssService = epssService,
        database = stubDatabase,
        nvdRepository = mockNvdRepository,
        nvdSyncService = mockNvdSyncService,
        leaderElection = mockLeaderElection,
        httpClient = client,
        vulnService = vulnService
    )

    attributes.put(DependenciesKey, dependencies)
}

fun Application.testModule(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    kevService: KevService = createMockCachedKevService(),
    epssService: EpssService = MockEpssService()
) {
    installTestDependencies(tokenIntrospectionService, naisApiService, kevService, epssService)

    install(ServerContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
        })
    }

    configureAuthentication(dependencies.tokenIntrospectionService)

    routing {
        healthRoutes()
        vulnRoutes()
    }
}

