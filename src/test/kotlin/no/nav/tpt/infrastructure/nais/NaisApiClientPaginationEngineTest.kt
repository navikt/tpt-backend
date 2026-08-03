package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.tpt.plugins.NaisApiException
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NaisApiClientPaginationEngineTest {
    companion object {
        val tokenFile: File = File.createTempFile("nais-token-engine-test", null).apply {
            writeText("test-token")
            deleteOnExit()
        }

        private val singlePageTeamResponse = """
            {
              "data": {
                "team": {
                  "slug": "test-team",
                  "applications": {
                    "pageInfo": { "hasNextPage": false, "endCursor": null },
                    "nodes": [
                      {
                        "id": "app-1", "name": "app-one",
                        "ingresses": [],
                        "deployments": { "nodes": [] },
                        "image": {
                          "name": "img", "tag": "1.0",
                          "vulnerabilities": {
                            "pageInfo": { "hasNextPage": false, "endCursor": null },
                            "nodes": [
                              { "identifier": "CVE-2024-0001", "severity": "HIGH",
                                "package": null, "description": null,
                                "vulnerabilityDetailsLink": null, "suppression": null }
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

        private fun teamResponseWithCursor(cursor: String, hasNext: Boolean, appId: String, appName: String) = """
            {
              "data": {
                "team": {
                  "slug": "test-team",
                  "applications": {
                    "pageInfo": { "hasNextPage": $hasNext, "endCursor": ${if (hasNext) "\"$cursor\"" else "null"} },
                    "nodes": [
                      {
                        "id": "$appId", "name": "$appName",
                        "ingresses": [],
                        "deployments": { "nodes": [] },
                        "image": {
                          "name": "img", "tag": "1.0",
                          "vulnerabilities": {
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

        private val emptyTeamResponse = """
            {
              "data": {
                "team": {
                  "slug": "test-team",
                  "applications": {
                    "pageInfo": { "hasNextPage": false, "endCursor": null },
                    "nodes": []
                  }
                }
              }
            }
        """.trimIndent()

        private val graphqlErrorResponse = """
            {
              "errors": [{ "message": "team not found", "path": ["team"] }]
            }
        """.trimIndent()
    }

    @Test
    fun `should collect all workloads across multiple pages`() = runTest {
        val requestCount = AtomicInteger(0)
        val mockEngine = MockEngine { _ ->
            when (requestCount.incrementAndGet()) {
                1 -> respond(
                    ByteReadChannel(teamResponseWithCursor("cursor1", true, "app-1", "first-app")),
                    HttpStatusCode.OK,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
                2 -> respond(
                    ByteReadChannel(teamResponseWithCursor("cursor2", true, "app-2", "second-app")),
                    HttpStatusCode.OK,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
                3 -> respond(
                    ByteReadChannel(teamResponseWithCursor("cursor3", false, "app-3", "third-app")),
                    HttpStatusCode.OK,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
                // jobs fetch — empty
                else -> respond(
                    ByteReadChannel("""{"data":{"team":{"slug":"test-team","jobs":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}}}"""),
                    HttpStatusCode.OK,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)
        val result = client.getVulnerabilitiesForTeam("test-team")

        assertEquals(1, result.teams.size)
        val workloads = result.teams.first().workloads
        assertEquals(3, workloads.size)
        assertTrue(workloads.map { it.name }.containsAll(listOf("first-app", "second-app", "third-app")))
    }

    @Test
    fun `should return empty workloads when first page has no items`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                ByteReadChannel(emptyTeamResponse),
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)
        val result = client.getVulnerabilitiesForTeam("test-team")

        assertEquals(1, result.teams.size)
        assertEquals(0, result.teams.first().workloads.size)
    }

    @Test
    fun `should throw NaisApiException when GraphQL returns errors`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                ByteReadChannel(graphqlErrorResponse),
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)

        assertFailsWith<NaisApiException> {
            client.getVulnerabilitiesForTeam("test-team")
        }
    }

    @Test
    fun `should throw NaisApiException when HTTP transport fails`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                ByteReadChannel(""),
                HttpStatusCode.InternalServerError,
                headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)

        assertFailsWith<NaisApiException> {
            client.getVulnerabilitiesForTeam("test-team")
        }
    }

    @Test
    fun `should collect single-page result without following cursor`() = runTest {
        val requestCount = AtomicInteger(0)
        val mockEngine = MockEngine { _ ->
            requestCount.incrementAndGet()
            respond(
                ByteReadChannel(singlePageTeamResponse),
                HttpStatusCode.OK,
                headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)
        val result = client.getVulnerabilitiesForTeam("test-team")

        assertEquals(1, result.teams.first().workloads.size)
        assertEquals("CVE-2024-0001", result.teams.first().workloads.first().vulnerabilities.first().identifier)
        // Only 2 requests expected: one for apps, one for jobs
        assertEquals(2, requestCount.get())
    }

    private fun createTestHttpClient(mockEngine: MockEngine) =
        HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(
                    Json {
                        prettyPrint = true
                        isLenient = true
                        ignoreUnknownKeys = true
                        explicitNulls = false
                        coerceInputValues = true
                    }
                )
            }
        }
}
