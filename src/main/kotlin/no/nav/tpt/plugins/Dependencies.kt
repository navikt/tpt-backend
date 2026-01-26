package no.nav.tpt.plugins

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.auth.NaisTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.*
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.database.DatabaseFactory
import no.nav.tpt.infrastructure.epss.*
import no.nav.tpt.infrastructure.nais.*
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.nvd.*
import no.nav.tpt.infrastructure.teamkatalogen.*
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.vulns.VulnService
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl
import no.nav.tpt.domain.user.UserContextService

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
    val gitHubRepository: GitHubRepository
)

val DependenciesKey = AttributeKey<Dependencies>("Dependencies")

val DependenciesPlugin = createApplicationPlugin(name = "Dependencies") {
    val config = AppConfig.fromEnvironment()

    val httpClient = HttpClient(CIO) {
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
        httpClient,
        config.naisApiUrl,
        config.naisApiToken
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

    val userContextService = UserContextServiceImpl(naisApiClient, teamkatalogenService)

    val gitHubRepository = GitHubRepositoryImpl(database)

    val vulnService = VulnServiceImpl(naisApiClient, kevService, epssService, nvdRepository, riskScorer, userContextService, gitHubRepository)

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
        gitHubRepository = gitHubRepository
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies

