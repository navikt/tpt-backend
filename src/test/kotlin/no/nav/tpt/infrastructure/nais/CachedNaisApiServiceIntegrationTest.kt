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
    fun `getVulnerabilitiesForUser should cache successful response`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            val response = if (requestCount % 2 == 1) {
                generateVulnerabilitiesResponse()
            } else {
                generateEmptyJobsResponse()
            }
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

        // First call - should hit the API (2 requests: apps + jobs)
        val result1 = cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(2, requestCount, "First call should hit the API twice (apps + jobs)")
        assertEquals(1, result1.teams.size)
        assertEquals(1, result1.teams[0].workloads.size)
        assertEquals(2, result1.teams[0].workloads[0].vulnerabilities.size)

        // Second call - should use cache
        val result2 = cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(2, requestCount, "Second call should use cache, not hit API")
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

        // First call - should hit the API (2 requests: apps + jobs)
        cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(2, requestCount, "First call should hit the API twice")

        // Second call - should hit API again because error response was not cached
        cachedService.getVulnerabilitiesForUser("test@example.com")
        assertEquals(4, requestCount, "Error responses should not be cached, should hit API twice again")

        httpClient.close()
    }

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
                      "applications": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "app-1",
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": "navikt/app-1",
                                  "environmentName": "production"
                                }
                              ]
                            },
                            "image": {
                              "name": "image-1",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": { "hasNextPage": false, "endCursor": null },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-0001",
                                    "severity": "HIGH",
                                    "package": "pkg:golang/example.com/pkg1@v1.0.0",
                                    "description": "Test vulnerability",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
                                    "suppression": null
                                  },
                                  {
                                    "identifier": "CVE-2023-0002",
                                    "severity": "MEDIUM",
                                    "package": "pkg:golang/example.com/pkg2@v1.0.0",
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

    private fun generateEmptyJobsResponse(): String = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": { "hasNextPage": false, "endCursor": null },
                "nodes": [
                  {
                    "team": {
                      "slug": "team-1",
                      "jobs": {
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
}

