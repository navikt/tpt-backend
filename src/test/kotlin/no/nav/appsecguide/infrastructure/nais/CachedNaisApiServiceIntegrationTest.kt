package no.nav.appsecguide.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.minutes


class CachedNaisApiServiceIntegrationTest {

    companion object {
        private lateinit var valkeyContainer: GenericContainer<*>
        private lateinit var teamIngressCache: ValkeyCache<String, TeamIngressTypesResponse>
        private lateinit var userAppsCache: ValkeyCache<String, ApplicationsForUserResponse>

        @JvmStatic
        @BeforeAll
        fun setup() {
            valkeyContainer = GenericContainer(DockerImageName.parse("ghcr.io/valkey-io/valkey:7.2-alpine"))
                .withExposedPorts(6379)
            valkeyContainer.start()

            val host = valkeyContainer.host
            val port = valkeyContainer.getMappedPort(6379)
            val valkeyUri = "redis://$host:$port"

            val pool = createTestValkeyPool(valkeyUri)
            teamIngressCache = ValkeyCache(
                pool = pool,
                ttl = 5.minutes,
                keyPrefix = "nais-team-ingress-test",
                valueSerializer = TeamIngressTypesResponse.serializer()
            )
            userAppsCache = ValkeyCache(
                pool = pool,
                ttl = 5.minutes,
                keyPrefix = "nais-user-apps-test",
                valueSerializer = ApplicationsForUserResponse.serializer()
            )
        }

        private fun createTestValkeyPool(uri: String): io.valkey.JedisPool {
            val valkeyUri = java.net.URI.create(uri)
            val poolConfig = io.valkey.JedisPoolConfig().apply {
                maxTotal = 20
                maxIdle = 10
                minIdle = 5
            }
            return io.valkey.JedisPool(poolConfig, valkeyUri)
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            teamIngressCache.close()
            userAppsCache.close()
            valkeyContainer.stop()
        }
    }

    @Test
    fun `should cache NAIS API responses`() = runTest {
        teamIngressCache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """
                    {
                        "data": {
                            "team": {
                                "applications": {
                                    "pageInfo": {
                                        "hasNextPage": false,
                                        "endCursor": null
                                    },
                                    "edges": [
                                        {
                                            "node": {
                                                "name": "test-app",
                                                "ingresses": [
                                                    {
                                                        "type": "internal"
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val naisApiClient = NaisApiClient(httpClient, "http://test", "test-token")
        val cachedService = CachedNaisApiService(naisApiClient, teamIngressCache, userAppsCache)

        val response1 = cachedService.getTeamIngressTypes("test-team")
        val response2 = cachedService.getTeamIngressTypes("test-team")
        val response3 = cachedService.getTeamIngressTypes("test-team")

        assertEquals(1, apiCallCount, "API should only be called once due to caching")
        assertEquals(response1.data?.team?.applications?.edges?.size, response2.data?.team?.applications?.edges?.size)
        assertEquals(response1.data?.team?.applications?.edges?.size, response3.data?.team?.applications?.edges?.size)
    }

    @Test
    fun `should not cache error responses`() = runTest {
        teamIngressCache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """{"errors":[{"message":"Team not found"}]}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val naisApiClient = NaisApiClient(httpClient, "http://test", "test-token")
        val cachedService = CachedNaisApiService(naisApiClient, teamIngressCache, userAppsCache)

        cachedService.getTeamIngressTypes("nonexistent-team")
        cachedService.getTeamIngressTypes("nonexistent-team")

        assertEquals(2, apiCallCount, "Error responses should not be cached")
    }

    @Test
    fun `should generate different cache keys for different teams`() = runTest {
        teamIngressCache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """
                    {
                        "data": {
                            "team": {
                                "applications": {
                                    "pageInfo": {
                                        "hasNextPage": false,
                                        "endCursor": null
                                    },
                                    "edges": []
                                }
                            }
                        }
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val naisApiClient = NaisApiClient(httpClient, "http://test", "test-token")
        val cachedService = CachedNaisApiService(naisApiClient, teamIngressCache, userAppsCache)

        cachedService.getTeamIngressTypes("team1")
        cachedService.getTeamIngressTypes("team2")
        cachedService.getTeamIngressTypes("team1")
        cachedService.getTeamIngressTypes("team2")

        assertEquals(2, apiCallCount, "Should call API once per unique team")
    }
}

