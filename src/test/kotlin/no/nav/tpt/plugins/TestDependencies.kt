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
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.MockKevService
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.epss.MockEpssService
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.nvd.MockNvdRepository
import no.nav.tpt.infrastructure.teamkatalogen.MockTeamkatalogenService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.routes.adminRoutes
import no.nav.tpt.routes.configRoutes
import no.nav.tpt.routes.healthRoutes
import no.nav.tpt.routes.vulnRoutes
import no.nav.tpt.routes.vulnerabilitySearchRoutes
import kotlin.time.Duration.Companion.seconds

fun Application.installTestDependencies(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    kevService: KevService = MockKevService(),
    epssService: EpssService = MockEpssService(),
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
        naisApiToken = "test-token",
        dbJdbcUrl = "jdbc:postgresql://localhost:5432/test_db?user=test&password=test",
        nvdApiUrl = "http://localhost:8080/mock-nvd-api",
        nvdApiKey = null,
        epssApiUrl = "http://localhost:8080/mock-epss-api",
        teamkatalogenUrl = "http://localhost:8080/mock-teamkatalogen",
        adminGroups = null,
        aiModel = "gpt-null",
        aiApiUrl = null
    )

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()

    // Mock NVD services for tests (not using real database)
    val mockNvdRepository = no.nav.tpt.infrastructure.nvd.MockNvdRepository()
    val mockNvdSyncService = no.nav.tpt.infrastructure.nvd.MockNvdSyncService()

    val actualAdminAuthorizationService = adminAuthorizationService ?: no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl()
    val actualUserContextService = userContextService ?: UserContextServiceImpl(naisApiService, teamkatalogenService, actualAdminAuthorizationService)

    val vulnerabilityDataService = object : no.nav.tpt.domain.vulnerability.VulnerabilityDataService {
        override suspend fun getVulnerabilitiesForUser(email: String) = 
            naisApiService.getVulnerabilitiesForUser(email)
    }
    
    val vulnService = VulnServiceImpl(
        vulnerabilityDataService = vulnerabilityDataService,
        kevService = kevService,
        epssService = MockEpssService(),
        nvdRepository = MockNvdRepository(),
        riskScorer = riskScorer,
        userContextService = actualUserContextService,
        gitHubRepository = no.nav.tpt.infrastructure.github.MockGitHubRepository()
    )

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

    val gitHubRepository: GitHubRepository = GitHubRepositoryImpl(stubDatabase)

    val mockVulnerabilityRepository = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
    
    val mockVulnerabilityTeamSyncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(
        naisApiService = naisApiService,
        vulnerabilityRepository = mockVulnerabilityRepository
    )
    
    val mockVulnerabilityDataSyncJob = no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob(
        naisApiService = naisApiService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        vulnerabilityRepository = mockVulnerabilityRepository,
        leaderElection = mockLeaderElection,
        teamDelayMs = 1000
    )
    
    val mockVulnerabilitySearchService = no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService(
        vulnerabilityRepository = mockVulnerabilityRepository
    )
    
    val mockAdminService = no.nav.tpt.infrastructure.admin.AdminServiceImpl(
        vulnerabilityRepository = mockVulnerabilityRepository
    )

    val dependencies = Dependencies(
        appConfig = testConfig,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        kevService = kevService,
        epssService = epssService,
        database = stubDatabase,
        nvdRepository = mockNvdRepository,
        nvdSyncService = mockNvdSyncService,
        leaderElection = mockLeaderElection,
        httpClient = client,
        vulnService = vulnService,
        teamkatalogenService = teamkatalogenService,
        userContextService = actualUserContextService,
        adminAuthorizationService = actualAdminAuthorizationService,
        adminService = mockAdminService,
        gitHubRepository = gitHubRepository,
        vulnerabilityDataSyncJob = mockVulnerabilityDataSyncJob,
        vulnerabilitySearchService = mockVulnerabilitySearchService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        remediationService = null
    )

    attributes.put(DependenciesKey, dependencies)
}

fun Application.testModule(
    tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService(),
    naisApiService: NaisApiService = MockNaisApiService(),
    kevService: KevService = MockKevService(),
    epssService: EpssService = MockEpssService(),
    teamkatalogenService: TeamkatalogenService = MockTeamkatalogenService(),
    adminAuthorizationService: no.nav.tpt.domain.user.AdminAuthorizationService? = null
) {
    installTestDependencies(tokenIntrospectionService, naisApiService, kevService, epssService, teamkatalogenService, adminAuthorizationService = adminAuthorizationService)

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
        healthRoutes()
        configRoutes()
        vulnRoutes()
        vulnerabilitySearchRoutes()
        adminRoutes()
    }
}

