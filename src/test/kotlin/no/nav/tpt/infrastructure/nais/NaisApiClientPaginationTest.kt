package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class NaisApiClientPaginationTest {

    private val json = Json { ignoreUnknownKeys = true }

    data class VulnerabilityData(
        val identifier: String,
        val severity: String,
        val packageName: String,
        val description: String? = null,
        val vulnerabilityDetailsLink: String? = null,
        val suppression: String? = null
    )

    data class WorkloadData(
        val id: String,
        val name: String,
        val imageName: String,
        val imageTag: String,
        val vulnerabilities: List<VulnerabilityData> = emptyList(),
        val vulnPageInfo: PageInfo = PageInfo(false, null)
    )

    data class TeamData(
        val slug: String,
        val workloads: List<WorkloadData> = emptyList(),
        val workloadPageInfo: PageInfo = PageInfo(false, null)
    )

    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )

    private fun generateGraphQLResponse(
        teams: List<TeamData>,
        teamPageInfo: PageInfo
    ): String {
        val teamsJson = teams.joinToString(",\n") { team ->
            val workloadsJson = team.workloads.joinToString(",\n") { workload ->
                val vulnerabilitiesJson = workload.vulnerabilities.joinToString(",\n") { vuln ->
                    """
                      {
                        "identifier": "${vuln.identifier}",
                        "severity": "${vuln.severity}",
                        "package": ${vuln.packageName.let { "\"$it\"" }},
                        "description": ${vuln.description?.let { "\"$it\"" } ?: "null"},
                        "vulnerabilityDetailsLink": ${vuln.vulnerabilityDetailsLink?.let { "\"$it\"" } ?: "null"},
                        "suppression": ${vuln.suppression?.let { """{ "state": "$it" }""" } ?: "null"}
                      }
                    """.trimIndent()
                }

                """
                  {
                    "id": "${workload.id}",
                    "name": "${workload.name}",
                    "deployments": { "nodes": [] },
                    "image": {
                      "name": "${workload.imageName}",
                      "tag": "${workload.imageTag}",
                      "vulnerabilities": {
                        "pageInfo": {
                          "hasNextPage": ${workload.vulnPageInfo.hasNextPage},
                          "endCursor": ${workload.vulnPageInfo.endCursor?.let { "\"$it\"" } ?: "null"}
                        },
                        "nodes": [
                          $vulnerabilitiesJson
                        ]
                      }
                    }
                  }
                """.trimIndent()
            }

            """
              {
                "team": {
                  "slug": "${team.slug}",
                  "workloads": {
                    "pageInfo": {
                      "hasNextPage": ${team.workloadPageInfo.hasNextPage},
                      "endCursor": ${team.workloadPageInfo.endCursor?.let { "\"$it\"" } ?: "null"}
                    },
                    "nodes": [
                      $workloadsJson
                    ]
                  }
                }
              }
            """.trimIndent()
        }

        return """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": ${teamPageInfo.hasNextPage},
                  "endCursor": ${teamPageInfo.endCursor?.let { "\"$it\"" } ?: "null"}
                },
                "nodes": [
                  $teamsJson
                ]
              }
            }
          }
        }
        """.trimIndent()
    }

    private fun createMockClient(responses: Map<Int, String>): Pair<HttpClient, () -> Int> {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            val responseJson = responses[requestCount]
                ?: throw IllegalStateException("Unexpected request count: $requestCount")

            respond(
                content = responseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        return httpClient to { requestCount }
    }

    @Test
    fun `should paginate through multiple teams`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData("team-1", listOf(WorkloadData("workload-1", "app-1", "image-1", "1.0.0"))),
                    TeamData("team-2")
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "cursor-after-team2")
            ),
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData("team-3", listOf(WorkloadData("workload-3", "app-3", "image-3", "1.0.0")))
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            )
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(2, getRequestCount(), "Should make 2 requests for team pagination")
        assertEquals(3, response.data?.user?.teams?.nodes?.size, "Should have 3 teams")
        assertEquals("team-1", response.data?.user?.teams?.nodes?.get(0)?.team?.slug)
        assertEquals("team-2", response.data?.user?.teams?.nodes?.get(1)?.team?.slug)
        assertEquals("team-3", response.data?.user?.teams?.nodes?.get(2)?.team?.slug)

        httpClient.close()
    }

    @Test
    fun `should paginate through workloads within a team`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(WorkloadData("workload-1", "app-1", "image-1", "1.0.0")),
                        workloadPageInfo = PageInfo(hasNextPage = true, endCursor = "workload-cursor-1")
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(WorkloadData("workload-2", "app-2", "image-2", "1.0.0")),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            )
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(2, getRequestCount(), "Should make 2 requests for workload pagination")
        assertEquals(1, response.data?.user?.teams?.nodes?.size, "Should have 1 team")
        assertEquals("team-1", response.data?.user?.teams?.nodes?.get(0)?.team?.slug)
        assertEquals(2, response.data?.user?.teams?.nodes?.get(0)?.team?.workloads?.nodes?.size, "Should have 2 workloads")
        assertEquals("workload-1", response.data?.user?.teams?.nodes?.get(0)?.team?.workloads?.nodes?.get(0)?.id)
        assertEquals("workload-2", response.data?.user?.teams?.nodes?.get(0)?.team?.workloads?.nodes?.get(1)?.id)

        httpClient.close()
    }

    @Test
    fun `should handle both team and workload pagination`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(WorkloadData("workload-1-1", "app-1-1", "image-1-1", "1.0.0")),
                        workloadPageInfo = PageInfo(hasNextPage = true, endCursor = "workload-cursor-1")
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(WorkloadData("workload-1-2", "app-1-2", "image-1-2", "1.0.0")),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            3 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-2",
                        workloads = listOf(WorkloadData("workload-2-1", "app-2-1", "image-2-1", "1.0.0")),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            )
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(3, getRequestCount(), "Should make 3 requests total")
        assertEquals(2, response.data?.user?.teams?.nodes?.size, "Should have 2 teams")

        val team1 = response.data?.user?.teams?.nodes?.get(0)
        assertEquals("team-1", team1?.team?.slug)
        assertEquals(2, team1?.team?.workloads?.nodes?.size, "Team 1 should have 2 workloads")
        assertEquals("workload-1-1", team1?.team?.workloads?.nodes?.get(0)?.id)
        assertEquals("workload-1-2", team1?.team?.workloads?.nodes?.get(1)?.id)

        val team2 = response.data?.user?.teams?.nodes?.get(1)
        assertEquals("team-2", team2?.team?.slug)
        assertEquals(1, team2?.team?.workloads?.nodes?.size, "Team 2 should have 1 workload")
        assertEquals("workload-2-1", team2?.team?.workloads?.nodes?.get(0)?.id)

        httpClient.close()
    }

    @Test
    fun `should handle triple nested pagination with multiple teams, workloads, and vulnerabilities`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "team1-workload-1",
                                name = "app-1-1",
                                imageName = "image-1-1",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0001", "HIGH", "pkg1")),
                                vulnPageInfo = PageInfo(hasNextPage = true, endCursor = "team1-wl1-vuln-cursor-1")
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = true, endCursor = "team1-workload-cursor-1")
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "team1-workload-1",
                                name = "app-1-1",
                                imageName = "image-1-1",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0002", "MEDIUM", "pkg2")),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = true, endCursor = "team1-workload-cursor-1")
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            3 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "team1-workload-2",
                                name = "app-1-2",
                                imageName = "image-1-2",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0003", "LOW", "pkg3")),
                                vulnPageInfo = PageInfo(hasNextPage = true, endCursor = "team1-wl2-vuln-cursor-1")
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            4 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "team1-workload-2",
                                name = "app-1-2",
                                imageName = "image-1-2",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0004", "CRITICAL", "pkg4")),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            5 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-2",
                        workloads = listOf(
                            WorkloadData(
                                id = "team2-workload-1",
                                name = "app-2-1",
                                imageName = "image-2-1",
                                imageTag = "2.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0005", "HIGH", "pkg5")),
                                vulnPageInfo = PageInfo(hasNextPage = true, endCursor = "team2-wl1-vuln-cursor-1")
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            6 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-2",
                        workloads = listOf(
                            WorkloadData(
                                id = "team2-workload-1",
                                name = "app-2-1",
                                imageName = "image-2-1",
                                imageTag = "2.0.0",
                                vulnerabilities = listOf(VulnerabilityData("CVE-2023-0006", "MEDIUM", "pkg6")),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            )
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(6, getRequestCount(), "Should make 6 requests total for triple nested pagination")
        assertEquals(2, response.data?.user?.teams?.nodes?.size, "Should have 2 teams")

        val team1 = response.data?.user?.teams?.nodes?.get(0)
        assertEquals("team-1", team1?.team?.slug)
        assertEquals(2, team1?.team?.workloads?.nodes?.size, "Team 1 should have 2 workloads")

        val team1Workload1 = team1?.team?.workloads?.nodes?.get(0)
        assertEquals("team1-workload-1", team1Workload1?.id)
        assertEquals(2, team1Workload1?.image?.vulnerabilities?.nodes?.size, "Team 1 Workload 1 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0001", team1Workload1?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0002", team1Workload1?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val team1Workload2 = team1?.team?.workloads?.nodes?.get(1)
        assertEquals("team1-workload-2", team1Workload2?.id)
        assertEquals(2, team1Workload2?.image?.vulnerabilities?.nodes?.size, "Team 1 Workload 2 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0003", team1Workload2?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0004", team1Workload2?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val team2 = response.data?.user?.teams?.nodes?.get(1)
        assertEquals("team-2", team2?.team?.slug)
        assertEquals(1, team2?.team?.workloads?.nodes?.size, "Team 2 should have 1 workload")

        val team2Workload1 = team2?.team?.workloads?.nodes?.get(0)
        assertEquals("team2-workload-1", team2Workload1?.id)
        assertEquals(2, team2Workload1?.image?.vulnerabilities?.nodes?.size, "Team 2 Workload 1 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0005", team2Workload1?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0006", team2Workload1?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val totalVulns = response.data?.user?.teams?.nodes
            ?.flatMap { it.team.workloads.nodes }
            ?.sumOf { it.image?.vulnerabilities?.nodes?.size ?: 0 }
        assertEquals(6, totalVulns, "Should have 6 total vulnerabilities across all teams and workloads")

        httpClient.close()
    }
}

