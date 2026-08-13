package no.nav.tpt.plugins

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.principal
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.routing.*
import io.ktor.server.sse.SSE
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.enrichment.VulnerabilityEnrichmentServiceImpl
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityServiceImpl
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.teamkatalogen.MockTeamkatalogenService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.routes.adminRoutes
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.naisRoutes
import no.nav.tpt.routes.sseRoutes
import no.nav.tpt.routes.gitHubVulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilityRoutes
import no.nav.tpt.routes.vulnerabilitySearchRoutes
import kotlin.time.Duration.Companion.seconds
import no.nav.tpt.infrastructure.datacollector.FakeDataCollector
import no.nav.tpt.infrastructure.datacollector.FakeDatacollectorRepository
import no.nav.tpt.routes.dataCollectorRoutes

fun Application.installTestDependencies(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    teamkatalogenService: TeamkatalogenService = MockTeamkatalogenService(),
    userContextService: UserContextService? = null,
    adminAuthorizationService: no.nav.tpt.domain.user.AdminAuthorizationService? = null,
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
        naisTokenFilePath = "test-token",
        dbJdbcUrl = "jdbc:postgresql://localhost:5432/test_db?user=test&password=test",
        teamkatalogenUrl = "http://localhost:8080/mock-teamkatalogen",
        adminGroups = null,
        naisTokenRetrievalEndpoint = "http://localhost:8080/token"
    )

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()

    val actualAdminAuthorizationService = adminAuthorizationService ?: no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl()
    val actualUserContextService = userContextService ?: UserContextServiceImpl(naisApiService, teamkatalogenService, actualAdminAuthorizationService)

    val vulnerabilityDataService = object : no.nav.tpt.domain.vulnerability.VulnerabilityDataService {
        override suspend fun getVulnerabilitiesForTeams(teamSlugs: List<String>) =
            naisApiService.getVulnerabilitiesForUser("test@nav.no")
        override suspend fun getVulnerabilitiesForTeam(teamSlug: String) =
            naisApiService.getVulnerabilitiesForTeam(teamSlug)
    }

    val mockGcveRepository = no.nav.tpt.infrastructure.gcve.InMemoryGcveRepository()
    val mockGcveClient = no.nav.tpt.infrastructure.gcve.GcveClient(client, "http://localhost:8080/mock-gcve-api")
    val mockGcveSyncService = no.nav.tpt.infrastructure.gcve.GcveSyncService(mockGcveClient, mockGcveRepository)

    val vulnService = VulnerabilityEnrichmentServiceImpl(
        vulnerabilityDataService = vulnerabilityDataService,
        riskScorer = riskScorer,
        userContextService = actualUserContextService,
        gcveRepository = mockGcveRepository,
    )

    val gitHubVulnerabilityService = GitHubVulnerabilityServiceImpl(
        gitHubRepository = no.nav.tpt.infrastructure.github.MockGitHubRepository(),
        gcveRepository = mockGcveRepository,
        userContextService = actualUserContextService,
        riskScorer = riskScorer,
    )

    val stubDatabase = org.jetbrains.exposed.v1.jdbc.Database.connect(
        url = "jdbc:postgresql://stub:5432/stub",
        driver = "org.postgresql.Driver",
        user = "stub",
        password = "stub"
    )

    val mockLeaderElection = LeaderElection(client)

    val gitHubRepository: GitHubRepository = GitHubRepositoryImpl(stubDatabase)

    val mockVulnerabilityRepository = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()

    val mockVulnerabilityTeamSyncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(
        naisApiService = naisApiService,
        vulnerabilityRepository = mockVulnerabilityRepository
    )

    val mockAdminReportRepository = no.nav.tpt.infrastructure.admin.InMemoryAdminReportRepository()

    val mockVulnerabilityDataSyncJob = no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob(
        naisApiService = naisApiService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        vulnerabilityRepository = mockVulnerabilityRepository,
        adminReportRepository = mockAdminReportRepository,
        teamDelayMs = 1000
    )

    val mockVulnerabilitySearchService = no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService(
        vulnerabilityRepository = mockVulnerabilityRepository,
        slaPolicy = no.nav.tpt.domain.vulnerability.SlaPolicy(),
    )

    val mockAdminService = no.nav.tpt.infrastructure.admin.AdminServiceImpl(
        adminReportRepository = mockAdminReportRepository,
    )

    val sseEventBus = SseEventBus()

    val dataCollector = FakeDataCollector()

    val datacollectorRepository = FakeDatacollectorRepository()

    val dependencies = Dependencies(
        appConfig = testConfig,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        database = stubDatabase,
        leaderElection = mockLeaderElection,
        httpClient = client,
        vulnerabilityEnrichmentService = vulnService,
        teamkatalogenService = teamkatalogenService,
        userContextService = actualUserContextService,
        adminAuthorizationService = actualAdminAuthorizationService,
        adminService = mockAdminService,
        gitHubRepository = gitHubRepository,
        dataCollectorRepository = datacollectorRepository,
        gitHubVulnerabilityService = gitHubVulnerabilityService,
        vulnerabilityDataSyncJob = mockVulnerabilityDataSyncJob,
        vulnerabilitySearchService = mockVulnerabilitySearchService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        gcveRepository = mockGcveRepository,
        gcveSyncService = mockGcveSyncService,
        sseEventBus = sseEventBus,
        kafkaProducerService = null,
        dataCollector = dataCollector
    )

    attributes.put(DependenciesKey, dependencies)
}

fun Application.testModule(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    teamkatalogenService: TeamkatalogenService = MockTeamkatalogenService(),
    adminAuthorizationService: no.nav.tpt.domain.user.AdminAuthorizationService? = null
) {
    installTestDependencies(tokenIntrospectionService, naisApiService, teamkatalogenService, adminAuthorizationService = adminAuthorizationService)

    install(SSE)
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

    routing {
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
