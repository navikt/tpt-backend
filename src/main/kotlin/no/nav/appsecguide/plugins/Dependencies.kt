package no.nav.appsecguide.plugins

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.auth.NaisTokenIntrospectionService
import no.nav.appsecguide.infrastructure.auth.TokenIntrospectionService
import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import no.nav.appsecguide.infrastructure.cache.ValkeyClientFactory
import no.nav.appsecguide.infrastructure.cisa.*
import no.nav.appsecguide.infrastructure.config.AppConfig
import no.nav.appsecguide.infrastructure.nais.*
import kotlin.time.Duration.Companion.minutes

@Suppress("unused")
class Dependencies(
    config: AppConfig,
    val tokenIntrospectionService: TokenIntrospectionService,
    val naisApiService: NaisApiService,
    val kevService: CachedKevService,
    val httpClient: HttpClient
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
    val teamIngressCache = ValkeyCache<String, ApplicationsForTeamResponse>(
        pool = valkeyPool,
        ttl = config.cacheTtlMinutes.minutes,
        keyPrefix = "nais-team-apps",
        valueSerializer = ApplicationsForTeamResponse.serializer()
    )
    val userAppsCache = ValkeyCache<String, ApplicationsForUserResponse>(
        pool = valkeyPool,
        ttl = config.cacheTtlMinutes.minutes,
        keyPrefix = "nais-user-apps",
        valueSerializer = ApplicationsForUserResponse.serializer()
    )
    val naisApiService = CachedNaisApiService(naisApiClient, teamIngressCache, userAppsCache)

    val kevClient = KevClient(httpClient)
    val kevCache = ValkeyCache<String, KevCatalog>(
        pool = valkeyPool,
        ttl = 24.minutes * 60,
        keyPrefix = "kev",
        valueSerializer = KevCatalog.serializer()
    )
    val kevService = CachedKevService(kevClient, kevCache)

    val dependencies = Dependencies(
        config = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        kevService = kevService,
        httpClient = httpClient
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies

