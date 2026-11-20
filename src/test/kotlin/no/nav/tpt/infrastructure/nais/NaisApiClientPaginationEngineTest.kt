package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.http.content.TextContent
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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

        private val workloadWithMoreVulnerabilitiesResponse = """
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
                            "pageInfo": { "hasNextPage": true, "endCursor": "vuln-cursor" },
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

        private fun appPage(
            workloadCursor: String?,
            appId: String,
            vulnCursor: String?,
            cves: List<String>,
            errors: String? = null,
        ): String {
            fun cursorJson(cursor: String?) =
                """{ "hasNextPage": ${cursor != null}, "endCursor": ${cursor?.let { "\"$it\"" } ?: "null"} }"""
            val vulnNodes = cves.joinToString(",") {
                """{ "identifier": "$it", "severity": "HIGH", "package": null, "description": null,
                     "vulnerabilityDetailsLink": null, "suppression": null }"""
            }
            return """
                {
                  ${errors?.let { "\"errors\": $it," } ?: ""}
                  "data": { "team": { "slug": "test-team", "applications": {
                    "pageInfo": ${cursorJson(workloadCursor)},
                    "nodes": [{
                      "id": "$appId", "name": "$appId", "ingresses": [], "deployments": { "nodes": [] },
                      "image": { "name": "img", "tag": "1.0", "vulnerabilities": {
                        "pageInfo": ${cursorJson(vulnCursor)}, "nodes": [$vulnNodes]
                      } }
                    }]
                  } } }
                }
            """.trimIndent()
        }

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
    fun `should throw NaisApiException when a later vulnerability page fails`() = runTest {
        val requestCount = AtomicInteger(0)
        val mockEngine = MockEngine { _ ->
            when (requestCount.incrementAndGet()) {
                1 -> respond(
                    ByteReadChannel(workloadWithMoreVulnerabilitiesResponse),
                    HttpStatusCode.OK,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
                else -> respond(
                    ByteReadChannel(""),
                    HttpStatusCode.BadGateway,
                    headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)

        assertFailsWith<NaisApiException> {
            client.getVulnerabilitiesForTeam("test-team")
        }
        assertEquals(2, requestCount.get())
    }

    @Test
    fun `should throw NaisApiException when a vulnerability page contains GraphQL errors`() = runTest {
        val requestCount = AtomicInteger(0)
        val mockEngine = MockEngine { _ ->
            val content = when (requestCount.incrementAndGet()) {
                1 -> workloadWithMoreVulnerabilitiesResponse
                else -> appPage(
                    workloadCursor = null, appId = "app-1", vulnCursor = null, cves = listOf("CVE-2024-0002"),
                    errors = """[{ "message": "partial failure", "path": ["team"] }]""",
                )
            }
            respond(ByteReadChannel(content), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
        }

        val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)

        assertFailsWith<NaisApiException> {
            client.getVulnerabilitiesForTeam("test-team")
        }
    }

    @Test
    fun `should use the workload page cursor when paginating vulnerabilities beyond the first workload page`() =
        runTest {
            val mockEngine = MockEngine { request ->
                val body = Json.parseToJsonElement((request.body as TextContent).text).jsonObject
                val variables = body.getValue("variables").jsonObject
                val workloadAfter = variables["workloadAfter"]?.jsonPrimitive?.contentOrNull
                val vulnAfter = variables["vulnAfter"]?.jsonPrimitive?.contentOrNull
                val content = when {
                    "JobVulnerabilitiesForTeam" in body.getValue("query").jsonPrimitive.content ->
                        """{"data":{"team":{"slug":"test-team","jobs":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}}}"""
                    workloadAfter == "w1" && vulnAfter == "v1" ->
                        appPage(workloadCursor = null, appId = "app-2", vulnCursor = null, cves = listOf("CVE-2024-0002"))
                    workloadAfter == "w1" && vulnAfter == null ->
                        appPage(workloadCursor = null, appId = "app-2", vulnCursor = "v1", cves = listOf("CVE-2024-0001"))
                    workloadAfter == null && vulnAfter == null ->
                        appPage(workloadCursor = "w1", appId = "app-1", vulnCursor = null, cves = emptyList())
                    else -> error("Unexpected request variables: $variables")
                }
                respond(ByteReadChannel(content), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
            }

            val client = NaisApiClient(createTestHttpClient(mockEngine), "https://api.nais.io", tokenFile.absolutePath)
            val result = client.getVulnerabilitiesForTeam("test-team")

            val secondApp = result.teams.first().workloads.single { it.id == "app-2" }
            assertEquals(listOf("CVE-2024-0001", "CVE-2024-0002"), secondApp.vulnerabilities.map { it.identifier })
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
