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
import no.nav.tpt.infrastructure.cache.ValkeyCache
import no.nav.tpt.infrastructure.cache.ValkeyClientFactory
import no.nav.tpt.infrastructure.cisa.*
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.database.DatabaseFactory
import no.nav.tpt.infrastructure.epss.*
import no.nav.tpt.infrastructure.nais.*
import no.nav.tpt.infrastructure.nvd.*
import no.nav.tpt.infrastructure.vulns.VulnService
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl
import kotlin.time.Duration.Companion.minutes

@Suppress("unused")
class Dependencies(
    config: AppConfig,
    val tokenIntrospectionService: TokenIntrospectionService,
    val naisApiService: NaisApiService,
    val kevService: KevService,
    val epssService: EpssService,
    val database: org.jetbrains.exposed.sql.Database,
    val nvdRepository: NvdRepository,
    val nvdSyncService: NvdSyncService,
    val leaderElection: LeaderElection,
    val httpClient: HttpClient,
    val vulnService: VulnService
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

    val valkeyPool = ValkeyClientFactory.createPool(
        config.valkeyHost,
        config.valkeyPort,
        config.valkeyUsername,
        config.valkeyPassword
    )
    val naisApiCache = ValkeyCache<String, String>(
        pool = valkeyPool,
        ttl = config.cacheTtlMinutes.minutes,
        keyPrefix = "nais-api",
        valueSerializer = kotlinx.serialization.serializer()
    )
    val naisApiService = CachedNaisApiService(naisApiClient, naisApiCache)
    val kevClient = KevClient(httpClient)
    val kevCache = ValkeyCache<String, KevCatalog>(
        pool = valkeyPool,
        ttl = 24.minutes * 60,
        keyPrefix = "kev",
        valueSerializer = KevCatalog.serializer()
    )
    val kevService = CachedKevService(kevClient, kevCache)

    val epssClient = EpssClient(httpClient)
    val epssCache = ValkeyCache<String, EpssScore>(
        pool = valkeyPool,
        ttl = 24.minutes * 60,
        keyPrefix = "epss",
        valueSerializer = EpssScore.serializer()
    )
    val epssCircuitBreaker = ValkeyCircuitBreaker(
        pool = valkeyPool,
        keyPrefix = "epss"
    )
    val epssService = CachedEpssService(epssClient, epssCache, epssCircuitBreaker)

    val database = DatabaseFactory.init(config)
    val nvdClient = NvdClient(httpClient, config.nvdApiKey)
    val nvdRepository = NvdRepositoryImpl(database)
    val nvdSyncService = NvdSyncService(nvdClient, nvdRepository)

    val leaderElection = LeaderElection(httpClient)

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
    val vulnService = VulnServiceImpl(naisApiService, kevService, epssService, riskScorer)

    val dependencies = Dependencies(
        config = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        kevService = kevService,
        epssService = epssService,
        database = database,
        nvdRepository = nvdRepository,
        nvdSyncService = nvdSyncService,
        leaderElection = leaderElection,
        httpClient = httpClient,
        vulnService = vulnService
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies

