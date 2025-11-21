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
        private lateinit var naisApiCache: ValkeyCache<String, String>

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
            naisApiCache = ValkeyCache<String, String>(
                pool = pool,
                ttl = 5.minutes,
                keyPrefix = "nais-api-test",
                valueSerializer = kotlinx.serialization.serializer()
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
            valkeyContainer.stop()
        }
    }

    @Test
    fun `should cache NAIS API responses`() = runTest {
        var apiCallCount = 0

        val mockEngine = MockEngine { _ ->
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
                                    "nodes": [
                                        {
                                            "name": "test-app",
                                            "ingresses": [
                                                {
                                                    "type": "internal"
                                                }
                                            ]
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
        val cachedService = CachedNaisApiService(naisApiClient, naisApiCache)

        val response1 = cachedService.getApplicationsForTeam("test-team")
        val response2 = cachedService.getApplicationsForTeam("test-team")
        val response3 = cachedService.getApplicationsForTeam("test-team")

        assertEquals(1, apiCallCount, "API should only be called once due to caching")
        assertEquals(response1.applications.size, response2.applications.size)
        assertEquals(response1.applications.size, response3.applications.size)
        assertEquals("test-app", response1.applications.first().name)
    }

    @Test
    fun `should not cache error responses`() = runTest {
        var apiCallCount = 0

        val mockEngine = MockEngine { _ ->
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
        val cachedService = CachedNaisApiService(naisApiClient, naisApiCache)

        cachedService.getApplicationsForTeam("nonexistent-team")
        cachedService.getApplicationsForTeam("nonexistent-team")

        assertEquals(2, apiCallCount, "Error responses should not be cached")
    }

    @Test
    fun `should generate different cache keys for different teams`() = runTest {
        var apiCallCount = 0

        val mockEngine = MockEngine { _ ->
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
                                    "nodes": []
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
        val cachedService = CachedNaisApiService(naisApiClient, naisApiCache)

        cachedService.getApplicationsForTeam("team1")
        cachedService.getApplicationsForTeam("team2")
        cachedService.getApplicationsForTeam("team1")
        cachedService.getApplicationsForTeam("team2")

        assertEquals(2, apiCallCount, "Should call API once per unique team")
    }
}

