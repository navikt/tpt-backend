package no.nav.tpt.plugins

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import no.nav.tpt.domain.admin.AdminService
import no.nav.tpt.domain.user.AdminAuthorizationService
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.vulnerability.VulnerabilityDataService
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.admin.AdminServiceImpl
import no.nav.tpt.infrastructure.auth.NaisTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.KevClient
import no.nav.tpt.infrastructure.cisa.KevRepositoryImpl
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.KevServiceImpl
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.database.DatabaseFactory
import no.nav.tpt.infrastructure.epss.EpssClient
import no.nav.tpt.infrastructure.epss.EpssRepositoryImpl
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.epss.EpssServiceImpl
import no.nav.tpt.infrastructure.epss.InMemoryCircuitBreaker
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.nais.NaisApiClient
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.nvd.NvdClient
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.nvd.NvdRepositoryImpl
import no.nav.tpt.infrastructure.nvd.NvdSyncService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenClient
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenServiceImpl
import no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.vulnerability.DatabaseVulnerabilityService
import no.nav.tpt.domain.remediation.RemediationService
import no.nav.tpt.infrastructure.ai.GeminiVertexAiClient
import no.nav.tpt.infrastructure.remediation.RemediationCacheRepositoryImpl
import no.nav.tpt.infrastructure.remediation.RemediationServiceImpl
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityRepositoryImpl
import no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import no.nav.tpt.infrastructure.vulns.VulnService
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl

@Suppress("unused")
class Dependencies(
    val appConfig: AppConfig,
    val tokenIntrospectionService: TokenIntrospectionService,
    val naisApiService: NaisApiService,
    val kevService: KevService,
    val epssService: EpssService,
    val database: org.jetbrains.exposed.sql.Database,
    val nvdRepository: NvdRepository,
    val nvdSyncService: NvdSyncService,
    val leaderElection: LeaderElection,
    val httpClient: HttpClient,
    val vulnService: VulnService,
    val teamkatalogenService: TeamkatalogenService,
    val userContextService: UserContextService,
    val adminAuthorizationService: AdminAuthorizationService,
    val adminService: AdminService,
    val gitHubRepository: GitHubRepository,
    val vulnerabilityDataSyncJob: VulnerabilityDataSyncJob,
    val vulnerabilitySearchService: VulnerabilitySearchService,
    val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService,
    val remediationService: RemediationService?
)

val DependenciesKey = AttributeKey<Dependencies>("Dependencies")

val DependenciesPlugin = createApplicationPlugin(name = "Dependencies") {
    val logger = LoggerFactory.getLogger("Dependencies")
    val config = AppConfig.fromEnvironment()

    val httpClient = HttpClient(CIO) {
        install(UserAgent) {
            agent = "Nav TPT Backend"
        }
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
                explicitNulls = false  // Treat missing fields as null for nullable properties
                coerceInputValues = true  // Coerce unexpected values to defaults
            })
        }
    }

    val tokenIntrospectionService = NaisTokenIntrospectionService(
        httpClient,
        config.naisTokenIntrospectionEndpoint
    )

    val naisApiClient = NaisApiClient(
        httpClient = httpClient,
        apiUrl = config.naisApiUrl,
        token = config.naisApiToken
    )

    val database = DatabaseFactory.init(config)

    val kevClient = KevClient(httpClient)
    val kevRepository = KevRepositoryImpl(database)
    val kevService = KevServiceImpl(kevClient, kevRepository)

    val epssClient = EpssClient(httpClient, baseUrl = config.epssApiUrl)
    val epssRepository = EpssRepositoryImpl(database)
    val epssCircuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300)
    val epssService = EpssServiceImpl(epssClient, epssRepository, epssCircuitBreaker)
    val nvdClient = NvdClient(httpClient, apiKey = config.nvdApiKey, baseUrl = config.nvdApiUrl)
    val nvdRepository = NvdRepositoryImpl(database)
    val nvdSyncService = NvdSyncService(nvdClient, nvdRepository)

    val leaderElection = LeaderElection(httpClient)

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()

    val teamkatalogenClient = TeamkatalogenClient(httpClient, config.teamkatalogenUrl)
    val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

    val adminAuthorizationService = AdminAuthorizationServiceImpl(config.adminGroups)

    val userContextService = UserContextServiceImpl(naisApiClient, teamkatalogenService, adminAuthorizationService)

    val gitHubRepository = GitHubRepositoryImpl(database)

    val vulnerabilityRepository: VulnerabilityRepository = VulnerabilityRepositoryImpl()

    val vulnerabilityTeamSyncService = VulnerabilityTeamSyncService(
        naisApiService = naisApiClient,
        vulnerabilityRepository = vulnerabilityRepository
    )

    val vulnerabilityDataService: VulnerabilityDataService = DatabaseVulnerabilityService(
        vulnerabilityRepository = vulnerabilityRepository,
        userContextService = userContextService,
        naisApiService = naisApiClient,
        vulnerabilityTeamSyncService = vulnerabilityTeamSyncService
    )

    val vulnService = VulnServiceImpl(
        vulnerabilityDataService = vulnerabilityDataService,
        kevService = kevService,
        epssService = epssService,
        nvdRepository = nvdRepository,
        riskScorer = riskScorer,
        userContextService = userContextService,
        gitHubRepository = gitHubRepository
    )

    val vulnerabilityDataSyncJob = VulnerabilityDataSyncJob(
        naisApiService = naisApiClient,
        vulnerabilityTeamSyncService = vulnerabilityTeamSyncService,
        vulnerabilityRepository = vulnerabilityRepository,
        leaderElection = leaderElection
    )

    val vulnerabilitySearchService = VulnerabilitySearchService(vulnerabilityRepository)

    val adminService = AdminServiceImpl(
        vulnerabilityRepository = vulnerabilityRepository
    )

    val remediationService = config.aiApiUrl?.let { apiBaseUrl ->
        val aiClient = GeminiVertexAiClient(httpClient, apiBaseUrl, config.aiModel)
        val remediationCacheRepository = RemediationCacheRepositoryImpl(database)
        RemediationServiceImpl(
            aiClient = aiClient,
            cacheRepository = remediationCacheRepository,
            nvdRepository = nvdRepository,
            epssService = epssService,
            kevService = kevService
        )
    }.also {
        if (it == null) logger.warn("AI_API_URL not configured — remediation endpoint will be unavailable")
    }

    val dependencies = Dependencies(
        appConfig = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiClient,
        kevService = kevService,
        epssService = epssService,
        database = database,
        nvdRepository = nvdRepository,
        nvdSyncService = nvdSyncService,
        leaderElection = leaderElection,
        httpClient = httpClient,
        vulnService = vulnService,
        teamkatalogenService = teamkatalogenService,
        userContextService = userContextService,
        adminAuthorizationService = adminAuthorizationService,
        adminService = adminService,
        gitHubRepository = gitHubRepository,
        vulnerabilityDataSyncJob = vulnerabilityDataSyncJob,
        vulnerabilitySearchService = vulnerabilitySearchService,
        vulnerabilityTeamSyncService = vulnerabilityTeamSyncService,
        remediationService = remediationService
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies

