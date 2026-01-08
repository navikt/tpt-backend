package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.cache.ValkeyCache
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.minutes

class CachedNaisApiServiceIntegrationTest {

    companion object {
        private lateinit var valkeyContainer: GenericContainer<*>
        private lateinit var naisApiCache: ValkeyCache<String, String>
        private val json = Json { ignoreUnknownKeys = true }

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

    @BeforeEach
    fun clearCache() = runTest {
        naisApiCache.clear()
    }

    @Test
    fun `getApplicationsForUser should cache successful response`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = generateApplicationsResponse(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")
        val cachedService = CachedNaisApiService(apiClient, naisApiCache)

        // First call - should hit the API
        val result1 = cachedService.getApplicationsForUser("test@example.com")
        assertEquals(1, requestCount, "First call should hit the API")
        assertEquals(2, result1.teams.size)

        // Second call - should use cache
        val result2 = cachedService.getApplicationsForUser("test@example.com")
        assertEquals(1, requestCount, "Second call should use cache, not hit API")
        assertEquals(2, result2.teams.size)

        // Verify cache contains the data
        val cacheKey = "user:test@example.com"
        val cachedValue = naisApiCache.get(cacheKey)
        assertNotNull(cachedValue, "Cache should contain the response")

        httpClient.close()
    }

    @Test
    fun `getApplicationsForUser should not cache response with errors`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = generateApplicationsErrorResponse(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")
        val cachedService = CachedNaisApiService(apiClient, naisApiCache)

        // First call - should hit the API
        cachedService.getApplicationsForUser("test@example.com")
        assertEquals(1, requestCount)

        // Second call - should hit API again because error response was not cached
        cachedService.getApplicationsForUser("test@example.com")
        assertEquals(2, requestCount, "Error responses should not be cached")

        httpClient.close()
    }

    @Test
    fun `getVulnerabilitiesForUser should cache successful response`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = generateVulnerabilitiesResponse(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")
        val cachedService = CachedNaisApiService(apiClient, naisApiCache)

        // First call - should hit the API
        val result1 = cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(1, requestCount, "First call should hit the API")
        assertEquals(1, result1.teams.size)
        assertEquals(1, result1.teams[0].workloads.size)
        assertEquals(2, result1.teams[0].workloads[0].vulnerabilities.size)

        // Second call - should use cache
        val result2 = cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(1, requestCount, "Second call should use cache, not hit API")
        assertEquals(1, result2.teams.size)

        // Verify cache contains the data
        val cacheKey = "vulnerabilities:user:test@example.com"
        val cachedValue = naisApiCache.get(cacheKey)
        assertNotNull(cachedValue, "Cache should contain the response")

        httpClient.close()
    }

    @Test
    fun `getVulnerabilitiesForUser should not cache response with errors`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = generateVulnerabilitiesErrorResponse(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")
        val cachedService = CachedNaisApiService(apiClient, naisApiCache)

        // First call - should hit the API
        cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(1, requestCount)

        // Second call - should hit API again because error response was not cached
        cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(2, requestCount, "Error responses should not be cached")

        httpClient.close()
    }

    @Test
    fun `different users should have separate cache entries`() = runTest {
        var requestCount = 0
        val responsesByEmail = mutableMapOf<String, String>()

        val mockEngine = MockEngine { _ ->
            requestCount++
            val email = if (requestCount == 1) "user1@example.com" else "user2@example.com"
            val response = generateApplicationsResponse()
            responsesByEmail[email] = response
            respond(
                content = response,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")
        val cachedService = CachedNaisApiService(apiClient, naisApiCache)

        // Call for user1
        cachedService.getApplicationsForUser("user1@example.com")
        assertEquals(1, requestCount)

        // Call for user2
        cachedService.getApplicationsForUser("user2@example.com")
        assertEquals(2, requestCount, "Different users should have separate cache entries")

        // Call for user1 again - should use cache
        cachedService.getApplicationsForUser("user1@example.com")
        assertEquals(2, requestCount, "User1 should still use cache")

        // Call for user2 again - should use cache
        cachedService.getApplicationsForUser("user2@example.com")
        assertEquals(2, requestCount, "User2 should still use cache")

        httpClient.close()
    }

    @Test
    fun `cache integration with Valkey should persist across service instances`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = generateApplicationsResponse(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val apiClient = NaisApiClient(httpClient, "http://test-api", "test-token")

        // First service instance caches the data
        val service1 = CachedNaisApiService(apiClient, naisApiCache)
        val result1 = service1.getApplicationsForUser("test@example.com")
        assertEquals(1, requestCount)
        assertEquals(2, result1.teams.size)

        // Second service instance should use the cached data
        val service2 = CachedNaisApiService(apiClient, naisApiCache)
        val result2 = service2.getApplicationsForUser("test@example.com")
        assertEquals(1, requestCount, "Second instance should use cache from first instance")
        assertEquals(2, result2.teams.size)

        httpClient.close()
    }

    // Helper functions to generate mock responses
    private fun generateApplicationsResponse(): String = """
        {
          "data": {
            "user": {
              "teams": {
                "nodes": [
                  {
                    "team": {
                      "slug": "team-1",
                      "applications": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": [
                          {
                            "name": "app-1",
                            "ingresses": [
                              { "type": "https://app1.example.com" }
                            ],
                            "deployments": {
                              "nodes": [
                                { "environmentName": "production" }
                              ]
                            }
                          }
                        ]
                      }
                    }
                  },
                  {
                    "team": {
                      "slug": "team-2",
                      "applications": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": []
                      }
                    }
                  }
                ]
              }
            }
          }
        }
    """.trimIndent()

    private fun generateApplicationsErrorResponse(): String = """
        {
          "data": null,
          "errors": [
            {
              "message": "User not found",
              "path": ["user"]
            }
          ]
        }
    """.trimIndent()

    private fun generateVulnerabilitiesResponse(): String = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": { "hasNextPage": false, "endCursor": null },
                "nodes": [
                  {
                    "team": {
                      "slug": "team-1",
                      "workloads": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "app-1",
                            "deployments": { "nodes": [] },
                            "image": {
                              "name": "image-1",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": { "hasNextPage": false, "endCursor": null },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-0001",
                                    "severity": "HIGH",
                                    "package": "pkg1",
                                    "description": "Test vulnerability",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
                                    "suppression": null
                                  },
                                  {
                                    "identifier": "CVE-2023-0002",
                                    "severity": "MEDIUM",
                                    "package": "pkg2",
                                    "description": "Another test vulnerability",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-0002",
                                    "suppression": null
                                  }
                                ]
                              }
                            }
                          }
                        ]
                      }
                    }
                  }
                ]
              }
            }
          }
        }
    """.trimIndent()

    private fun generateVulnerabilitiesErrorResponse(): String = """
        {
          "data": null,
          "errors": [
            {
              "message": "Failed to fetch vulnerabilities",
              "path": ["user", "teams"]
            }
          ]
        }
    """.trimIndent()
}

