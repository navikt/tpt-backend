package no.nav.tpt.plugins

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.UserAgent
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.util.AttributeKey
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.admin.AdminService
import no.nav.tpt.domain.user.AdminAuthorizationService
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.vulnerability.SlaConfig
import no.nav.tpt.domain.vulnerability.SlaPolicy
import no.nav.tpt.domain.vulnerability.VulnerabilityDataService
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.admin.AdminReportRepository
import no.nav.tpt.infrastructure.admin.AdminReportRepositoryImpl
import no.nav.tpt.infrastructure.admin.AdminServiceImpl
import no.nav.tpt.infrastructure.auth.NaisTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.common.InMemoryCircuitBreaker
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.database.DatabaseFactory
import no.nav.tpt.infrastructure.datacollector.DataCollector
import no.nav.tpt.infrastructure.datacollector.RealDataCollector
import no.nav.tpt.infrastructure.gcve.GcveClient
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.gcve.GcveRepositoryImpl
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.enrichment.VulnerabilityEnrichmentService
import no.nav.tpt.infrastructure.enrichment.VulnerabilityEnrichmentServiceImpl
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityService
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityServiceImpl
import no.nav.tpt.infrastructure.kafka.KafkaProducerService
import no.nav.tpt.infrastructure.nais.NaisApiClient
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenClient
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenServiceImpl
import no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.vulnerability.DatabaseVulnerabilityService
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityRepositoryImpl
import no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import no.nav.tpt.infrastructure.kafka.KafkaConfig

@Suppress("unused")
class Dependencies(
    val appConfig: AppConfig,
    val tokenIntrospectionService: TokenIntrospectionService,
    val naisApiService: NaisApiService,
    val database: org.jetbrains.exposed.v1.jdbc.Database,
    val leaderElection: LeaderElection,
    val httpClient: HttpClient,
    val vulnerabilityEnrichmentService: VulnerabilityEnrichmentService,
    val teamkatalogenService: TeamkatalogenService,
    val userContextService: UserContextService,
    val adminAuthorizationService: AdminAuthorizationService,
    val adminService: AdminService,
    val gitHubRepository: GitHubRepository,
    val gitHubVulnerabilityService: GitHubVulnerabilityService,
    val vulnerabilityDataSyncJob: VulnerabilityDataSyncJob,
    val vulnerabilitySearchService: VulnerabilitySearchService,
    val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService,
    val gcveRepository: GcveRepository,
    val gcveSyncService: GcveSyncService,
    val sseEventBus: SseEventBus,
    val kafkaProducerService: KafkaProducerService?,
    val dataCollector: DataCollector
)

val DependenciesKey = AttributeKey<Dependencies>("Dependencies")

val DependenciesPlugin = createApplicationPlugin(name = "Dependencies") {
    val config = AppConfig.fromEnvironment()

    val httpClient = HttpClient(CIO) {
        install(UserAgent) {
            agent = "tpt-backend (+https://github.com/navikt/tpt-backend)"
        }
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
                explicitNulls = false
                coerceInputValues = true
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
        tokenFilePath = config.naisTokenFilePath
    )

    val database = DatabaseFactory.init(config)

    val leaderElection = LeaderElection(httpClient)

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()

    val teamkatalogenClient = TeamkatalogenClient(httpClient, config.teamkatalogenUrl)
    val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

    val adminAuthorizationService = AdminAuthorizationServiceImpl(config.adminGroups)

    val userContextService = UserContextServiceImpl(naisApiClient, teamkatalogenService, adminAuthorizationService)

    val gitHubRepository = GitHubRepositoryImpl(database)

    val slaPolicy = SlaPolicy(SlaConfig(
        criticalWorkdays = config.slaCriticalWorkdays,
        nonCriticalMonths = config.slaNonCriticalMonths,
    ))

    val vulnerabilityRepository: VulnerabilityRepository = VulnerabilityRepositoryImpl(slaPolicy)

    val vulnerabilityTeamSyncService = VulnerabilityTeamSyncService(
        naisApiService = naisApiClient,
        vulnerabilityRepository = vulnerabilityRepository
    )

    val sseEventBus = SseEventBus()

    val kafkaProducerService = KafkaConfig.fromEnvironment()?.let { KafkaProducerService(it) }

    val vulnerabilityDataService: VulnerabilityDataService = DatabaseVulnerabilityService(
        vulnerabilityRepository = vulnerabilityRepository,
        kafkaProducer = kafkaProducerService,
    )

    val adminReportRepository: AdminReportRepository = AdminReportRepositoryImpl(database)

    val gcveCircuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300)
    val gcveClient = GcveClient(httpClient, config.gcveApiUrl, config.gcveApiKey, gcveCircuitBreaker)
    val gcveRepository = GcveRepositoryImpl(database)
    val gcveSyncService = GcveSyncService(gcveClient, gcveRepository)

    val vulnService = VulnerabilityEnrichmentServiceImpl(
        vulnerabilityDataService = vulnerabilityDataService,
        riskScorer = riskScorer,
        userContextService = userContextService,
        gcveRepository = gcveRepository,
    )

    val gitHubVulnerabilityService = GitHubVulnerabilityServiceImpl(
        gitHubRepository = gitHubRepository,
        gcveRepository = gcveRepository,
        userContextService = userContextService,
        riskScorer = riskScorer,
    )

    val vulnerabilityDataSyncJob = VulnerabilityDataSyncJob(
        naisApiService = naisApiClient,
        vulnerabilityTeamSyncService = vulnerabilityTeamSyncService,
        vulnerabilityRepository = vulnerabilityRepository,
        adminReportRepository = adminReportRepository,
    )

    val vulnerabilitySearchService = VulnerabilitySearchService(vulnerabilityRepository, slaPolicy)

    val adminService = AdminServiceImpl(
        adminReportRepository = adminReportRepository,
    )

    val dataCollector =
        RealDataCollector(httpClient = httpClient, naisTokenEndpoint = config.naisTokenRetrievalEndpoint)

    val dependencies = Dependencies(
        appConfig = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiClient,
        database = database,
        leaderElection = leaderElection,
        httpClient = httpClient,
        vulnerabilityEnrichmentService = vulnService,
        teamkatalogenService = teamkatalogenService,
        userContextService = userContextService,
        adminAuthorizationService = adminAuthorizationService,
        adminService = adminService,
        gitHubRepository = gitHubRepository,
        gitHubVulnerabilityService = gitHubVulnerabilityService,
        vulnerabilityDataSyncJob = vulnerabilityDataSyncJob,
        vulnerabilitySearchService = vulnerabilitySearchService,
        vulnerabilityTeamSyncService = vulnerabilityTeamSyncService,
        gcveRepository = gcveRepository,
        gcveSyncService = gcveSyncService,
        sseEventBus = sseEventBus,
        kafkaProducerService = kafkaProducerService,
        dataCollector = dataCollector,
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies
