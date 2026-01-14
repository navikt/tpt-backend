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

    private fun generateEmptyJobsResponse(teamSlug: String = "team-1"): String = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": { "hasNextPage": false, "endCursor": null },
                "nodes": [
                  {
                    "team": {
                      "slug": "$teamSlug",
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

    private fun generateEmptyJobsResponseMultiTeam(teamSlugs: List<String>, teamPageInfo: PageInfo = PageInfo(false, null)): String {
        val teamsJson = teamSlugs.joinToString(",\n") { slug ->
            """
              {
                "team": {
                  "slug": "$slug",
                  "jobs": {
                    "pageInfo": { "hasNextPage": false, "endCursor": null },
                    "nodes": []
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
                    "deployments": {
                      "nodes": [
                        {
                          "repository": "navikt/${workload.name}",
                          "environmentName": "production"
                        }
                      ]
                    },
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
                  "applications": {
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
            // Apps requests
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
            ),
            // Jobs requests
            3 to generateEmptyJobsResponseMultiTeam(listOf("team-1", "team-2"), PageInfo(hasNextPage = true, endCursor = "cursor-after-team2")),
            4 to generateEmptyJobsResponseMultiTeam(listOf("team-3"), PageInfo(hasNextPage = false, endCursor = null))
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(4, getRequestCount(), "Should make 4 requests (2 for apps, 2 for jobs)")
        assertEquals(3, response.data?.user?.teams?.nodes?.size, "Should have 3 teams")
        assertEquals("team-1", response.data?.user?.teams?.nodes?.get(0)?.team?.slug)
        assertEquals("team-2", response.data?.user?.teams?.nodes?.get(1)?.team?.slug)
        assertEquals("team-3", response.data?.user?.teams?.nodes?.get(2)?.team?.slug)

        httpClient.close()
    }

    @Test
    fun `should paginate through workloads within a team`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            // Apps requests
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
            ),
            // Jobs request
            3 to generateEmptyJobsResponse("team-1")
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(3, getRequestCount(), "Should make 3 requests (2 for apps pagination, 1 for jobs)")
        assertEquals(1, response.data?.user?.teams?.nodes?.size, "Should have 1 team")
        assertEquals("team-1", response.data?.user?.teams?.nodes?.get(0)?.team?.slug)
        assertEquals(2, response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes?.size, "Should have 2 workloads")
        assertEquals("workload-1", response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes?.get(0)?.id)
        assertEquals("workload-2", response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes?.get(1)?.id)

        httpClient.close()
    }

    @Test
    fun `should handle both team and workload pagination`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            // Apps requests (all apps complete first)
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
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
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
            ),
            // Jobs requests (all jobs after apps complete)
            4 to generateEmptyJobsResponseMultiTeam(listOf("team-1"), PageInfo(hasNextPage = true, endCursor = "team-cursor-1")),
            5 to generateEmptyJobsResponseMultiTeam(listOf("team-2"), PageInfo(hasNextPage = false, endCursor = null))
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(5, getRequestCount(), "Should make 5 requests total (3 for apps, 2 for jobs)")
        assertEquals(2, response.data?.user?.teams?.nodes?.size, "Should have 2 teams")

        val team1 = response.data?.user?.teams?.nodes?.get(0)
        assertEquals("team-1", team1?.team?.slug)
        assertEquals(2, team1?.team?.applications?.nodes?.size, "Team 1 should have 2 workloads")
        assertEquals("workload-1-1", team1?.team?.applications?.nodes?.get(0)?.id)
        assertEquals("workload-1-2", team1?.team?.applications?.nodes?.get(1)?.id)

        val team2 = response.data?.user?.teams?.nodes?.get(1)
        assertEquals("team-2", team2?.team?.slug)
        assertEquals(1, team2?.team?.applications?.nodes?.size, "Team 2 should have 1 workload")
        assertEquals("workload-2-1", team2?.team?.applications?.nodes?.get(0)?.id)

        httpClient.close()
    }

    @Test
    fun `should handle triple nested pagination with multiple teams, workloads, and vulnerabilities`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            // All apps requests first - simplified to just team and workload pagination
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
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0001", "HIGH", "pkg1"),
                                    VulnerabilityData("CVE-2023-0002", "MEDIUM", "pkg2")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
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
                                id = "team1-workload-2",
                                name = "app-1-2",
                                imageName = "image-1-2",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0003", "LOW", "pkg3"),
                                    VulnerabilityData("CVE-2023-0004", "CRITICAL", "pkg4")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = true, endCursor = "team-cursor-1")
            ),
            3 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-2",
                        workloads = listOf(
                            WorkloadData(
                                id = "team2-workload-1",
                                name = "app-2-1",
                                imageName = "image-2-1",
                                imageTag = "2.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0005", "HIGH", "pkg5"),
                                    VulnerabilityData("CVE-2023-0006", "MEDIUM", "pkg6")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            // All jobs requests after apps complete
            4 to generateEmptyJobsResponseMultiTeam(listOf("team-1"), PageInfo(hasNextPage = true, endCursor = "team-cursor-1")),
            5 to generateEmptyJobsResponseMultiTeam(listOf("team-2"), PageInfo(hasNextPage = false, endCursor = null))
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(5, getRequestCount(), "Should make 5 requests total (3 for apps, 2 for jobs)")
        assertEquals(2, response.data?.user?.teams?.nodes?.size, "Should have 2 teams")

        val team1 = response.data?.user?.teams?.nodes?.get(0)
        assertEquals("team-1", team1?.team?.slug)
        assertEquals(2, team1?.team?.applications?.nodes?.size, "Team 1 should have 2 workloads")

        val team1Workload1 = team1?.team?.applications?.nodes?.get(0)
        assertEquals("team1-workload-1", team1Workload1?.id)
        assertEquals(2, team1Workload1?.image?.vulnerabilities?.nodes?.size, "Team 1 Workload 1 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0001", team1Workload1?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0002", team1Workload1?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val team1Workload2 = team1?.team?.applications?.nodes?.get(1)
        assertEquals("team1-workload-2", team1Workload2?.id)
        assertEquals(2, team1Workload2?.image?.vulnerabilities?.nodes?.size, "Team 1 Workload 2 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0003", team1Workload2?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0004", team1Workload2?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val team2 = response.data?.user?.teams?.nodes?.get(1)
        assertEquals("team-2", team2?.team?.slug)
        assertEquals(1, team2?.team?.applications?.nodes?.size, "Team 2 should have 1 workload")

        val team2Workload1 = team2?.team?.applications?.nodes?.get(0)
        assertEquals("team2-workload-1", team2Workload1?.id)
        assertEquals(2, team2Workload1?.image?.vulnerabilities?.nodes?.size, "Team 2 Workload 1 should have 2 vulnerabilities")
        assertEquals("CVE-2023-0005", team2Workload1?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0006", team2Workload1?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        val totalVulns = response.data?.user?.teams?.nodes
            ?.flatMap { it.team.applications?.nodes ?: emptyList() }
            ?.sumOf { it.image?.vulnerabilities?.nodes?.size ?: 0 }
        assertEquals(6, totalVulns, "Should have 6 total vulnerabilities across all teams and workloads")

        httpClient.close()
    }

    @Test
    fun `should paginate vulnerabilities for workloads from first page`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            // Apps requests
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app-1",
                                imageName = "image-1",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0001", "HIGH", "pkg1"),
                                    VulnerabilityData("CVE-2023-0002", "MEDIUM", "pkg2")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = true, endCursor = "vuln-cursor-1")
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app-1",
                                imageName = "image-1",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0003", "LOW", "pkg3"),
                                    VulnerabilityData("CVE-2023-0004", "CRITICAL", "pkg4")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            // Jobs request
            3 to generateEmptyJobsResponse("team-1")
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(3, getRequestCount(), "Should make 3 requests (2 for vuln pagination, 1 for jobs)")
        val workload = response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes?.get(0)
        assertEquals("workload-1", workload?.id)
        assertEquals(4, workload?.image?.vulnerabilities?.nodes?.size, "Should have all 4 vulnerabilities")
        assertEquals("CVE-2023-0001", workload?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0002", workload?.image?.vulnerabilities?.nodes?.get(1)?.identifier)
        assertEquals("CVE-2023-0003", workload?.image?.vulnerabilities?.nodes?.get(2)?.identifier)
        assertEquals("CVE-2023-0004", workload?.image?.vulnerabilities?.nodes?.get(3)?.identifier)

        httpClient.close()
    }

    @Test
    fun `should paginate vulnerabilities for workloads from paginated workload pages`() = runTest {
        val (httpClient, getRequestCount) = createMockClient(mapOf(
            // First page of workloads
            1 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app-1",
                                imageName = "image-1",
                                imageTag = "1.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0001", "HIGH", "pkg1")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = true, endCursor = "workload-cursor-1")
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            // Second page of workloads - THIS workload has vulnerability pagination
            2 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-2",
                                name = "app-2",
                                imageName = "image-2",
                                imageTag = "2.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0002", "MEDIUM", "pkg2"),
                                    VulnerabilityData("CVE-2023-0003", "HIGH", "pkg3")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = true, endCursor = "vuln-cursor-1")
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            // Vulnerability pagination for workload-2
            3 to generateGraphQLResponse(
                teams = listOf(
                    TeamData(
                        slug = "team-1",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-2",
                                name = "app-2",
                                imageName = "image-2",
                                imageTag = "2.0.0",
                                vulnerabilities = listOf(
                                    VulnerabilityData("CVE-2023-0004", "CRITICAL", "pkg4"),
                                    VulnerabilityData("CVE-2023-0005", "LOW", "pkg5")
                                ),
                                vulnPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                            )
                        ),
                        workloadPageInfo = PageInfo(hasNextPage = false, endCursor = null)
                    )
                ),
                teamPageInfo = PageInfo(hasNextPage = false, endCursor = null)
            ),
            // Jobs request
            4 to generateEmptyJobsResponse("team-1")
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(4, getRequestCount(), "Should make 4 requests (1 workload page 1, 1 workload page 2, 1 vuln pagination for workload-2, 1 jobs)")

        val workloads = response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes
        assertEquals(2, workloads?.size, "Should have 2 workloads")

        val workload1 = workloads?.get(0)
        assertEquals("workload-1", workload1?.id)
        assertEquals(1, workload1?.image?.vulnerabilities?.nodes?.size, "Workload 1 should have 1 vulnerability")

        val workload2 = workloads?.get(1)
        assertEquals("workload-2", workload2?.id)
        assertEquals(4, workload2?.image?.vulnerabilities?.nodes?.size, "Workload 2 should have all 4 vulnerabilities from pagination")
        assertEquals("CVE-2023-0002", workload2?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0003", workload2?.image?.vulnerabilities?.nodes?.get(1)?.identifier)
        assertEquals("CVE-2023-0004", workload2?.image?.vulnerabilities?.nodes?.get(2)?.identifier)
        assertEquals("CVE-2023-0005", workload2?.image?.vulnerabilities?.nodes?.get(3)?.identifier)

        httpClient.close()
    }

    @Test
    fun `should preserve ingresses through vulnerability pagination`() = runTest {
        val responseWithIngresses = """
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
                            "ingresses": [
                              { "type": "AUTHENTICATED" },
                              { "type": "EXTERNAL" }
                            ],
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
                                "pageInfo": {
                                  "hasNextPage": true,
                                  "endCursor": "vuln-cursor-1"
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-0001",
                                    "severity": "HIGH",
                                    "package": "pkg1",
                                    "description": null,
                                    "vulnerabilityDetailsLink": null,
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

        val responseSecondVulnPage = """
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
                            "ingresses": [
                              { "type": "AUTHENTICATED" },
                              { "type": "EXTERNAL" }
                            ],
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
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-0002",
                                    "severity": "MEDIUM",
                                    "package": "pkg2",
                                    "description": null,
                                    "vulnerabilityDetailsLink": null,
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

        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to responseWithIngresses,
            2 to responseSecondVulnPage,
            3 to generateEmptyJobsResponse("team-1")
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(3, getRequestCount(), "Should make 3 requests")

        val workload = response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes?.get(0)
        assertEquals("workload-1", workload?.id)
        assertEquals(2, workload?.ingresses?.size, "Should preserve ingresses")
        assertEquals("AUTHENTICATED", workload?.ingresses?.get(0)?.type)
        assertEquals("EXTERNAL", workload?.ingresses?.get(1)?.type)
        assertEquals(2, workload?.image?.vulnerabilities?.nodes?.size, "Should have both vulnerabilities")
        assertEquals("CVE-2023-0001", workload?.image?.vulnerabilities?.nodes?.get(0)?.identifier)
        assertEquals("CVE-2023-0002", workload?.image?.vulnerabilities?.nodes?.get(1)?.identifier)

        httpClient.close()
    }

    @Test
    fun `should preserve ingresses through workload pagination`() = runTest {
        val firstWorkloadPage = """
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
                        "pageInfo": { "hasNextPage": true, "endCursor": "workload-cursor-1" },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "app-1",
                            "ingresses": [
                              { "type": "INTERNAL" }
                            ],
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
                                    "package": "pkg1",
                                    "description": null,
                                    "vulnerabilityDetailsLink": null,
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

        val secondWorkloadPage = """
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
                            "id": "workload-2",
                            "name": "app-2",
                            "ingresses": [
                              { "type": "AUTHENTICATED" }
                            ],
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": "navikt/app-2",
                                  "environmentName": "production"
                                }
                              ]
                            },
                            "image": {
                              "name": "image-2",
                              "tag": "2.0.0",
                              "vulnerabilities": {
                                "pageInfo": { "hasNextPage": false, "endCursor": null },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-0002",
                                    "severity": "MEDIUM",
                                    "package": "pkg2",
                                    "description": null,
                                    "vulnerabilityDetailsLink": null,
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

        val (httpClient, getRequestCount) = createMockClient(mapOf(
            1 to firstWorkloadPage,
            2 to secondWorkloadPage,
            3 to generateEmptyJobsResponse("team-1")
        ))

        val client = NaisApiClient(httpClient, "http://test-api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertEquals(3, getRequestCount(), "Should make 3 requests")

        val workloads = response.data?.user?.teams?.nodes?.get(0)?.team?.applications?.nodes
        assertEquals(2, workloads?.size, "Should have 2 workloads")

        val workload1 = workloads?.get(0)
        assertEquals("workload-1", workload1?.id)
        assertEquals(1, workload1?.ingresses?.size, "Should preserve ingresses for workload 1")
        assertEquals("INTERNAL", workload1?.ingresses?.get(0)?.type)

        val workload2 = workloads?.get(1)
        assertEquals("workload-2", workload2?.id)
        assertEquals(1, workload2?.ingresses?.size, "Should preserve ingresses for workload 2")
        assertEquals("AUTHENTICATED", workload2?.ingresses?.get(0)?.type)

        httpClient.close()
    }

}

