package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NaisApiClientTeamVulnerabilitiesTest {
    @Test
    fun `should parse team vulnerabilities response correctly`() =
        runTest {
            val mockEngine =
                MockEngine { request ->
                    respond(
                        content =
                            ByteReadChannel(
                                """
                                {
                                  "data": {
                                    "team": {
                                      "slug": "test-team",
                                      "applications": {
                                        "pageInfo": {
                                          "hasNextPage": false,
                                          "endCursor": null
                                        },
                                        "nodes": [
                                          {
                                            "id": "app-1",
                                            "name": "test-app",
                                            "ingresses": [
                                              {
                                                "type": "EXTERNAL"
                                              }
                                            ],
                                            "deployments": {
                                              "nodes": [
                                                {
                                                  "repository": "navikt/test-app",
                                                  "environmentName": "prod"
                                                }
                                              ]
                                            },
                                            "image": {
                                              "name": "test-app",
                                              "tag": "1.0.0",
                                              "vulnerabilities": {
                                                "pageInfo": {
                                                  "hasNextPage": false,
                                                  "endCursor": null
                                                },
                                                "nodes": [
                                                  {
                                                    "identifier": "CVE-2024-1234",
                                                    "description": "Test vulnerability",
                                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                                                    "severity": "HIGH",
                                                    "package": "test-package",
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
                                }
                                """.trimIndent(),
                            ),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            assertEquals(1, response.teams.size)
            assertEquals("test-team", response.teams.first().teamSlug)
            assertEquals(
                1,
                response.teams
                    .first()
                    .workloads.size,
            )
            val workload =
                response.teams
                    .first()
                    .workloads
                    .first()
            assertEquals("test-app", workload.name)
            assertEquals("app", workload.workloadType)
            assertEquals(1, workload.vulnerabilities.size)
            assertEquals("CVE-2024-1234", workload.vulnerabilities.first().identifier)
            assertEquals("HIGH", workload.vulnerabilities.first().severity)
        }

    @Test
    fun `should throw exception when team not found`() =
        runTest {
            val mockEngine =
                MockEngine { request ->
                    respond(
                        content =
                            ByteReadChannel(
                                """
                                {
                                  "errors": [
                                    {
                                      "message": "Team not found",
                                      "path": ["team"]
                                    }
                                  ],
                                  "data": null
                                }
                                """.trimIndent(),
                            ),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val exception =
                kotlin
                    .runCatching {
                        naisApiClient.getVulnerabilitiesForTeam("nonexistent-team")
                    }.exceptionOrNull()

            assertNotNull(exception)
            assertTrue(exception.message?.contains("GraphQL errors") == true)
            assertTrue(exception.message?.contains("Team not found") == true)
        }

    @Test
    fun `should handle team with no applications or jobs`() =
        runTest {
            val mockEngine =
                MockEngine { request ->
                    respond(
                        content =
                            ByteReadChannel(
                                """
                                {
                                  "data": {
                                    "team": {
                                      "slug": "empty-team",
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
                            ),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("empty-team")

            assertNotNull(response)
            assertEquals("empty-team", response.teams.first().teamSlug)
            assertEquals(
                0,
                response.teams
                    .first()
                    .workloads.size,
            )
        }

    @Test
    fun `should handle workload pagination correctly`() =
        runTest {
            var requestCount = 0
            val mockEngine =
                MockEngine { request ->
                    requestCount++
                    val responseJson =
                        when (requestCount) {
                            1 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "applications": {
                            "pageInfo": {
                              "hasNextPage": true,
                              "endCursor": "cursor-1"
                            },
                            "nodes": [
                              {
                                "id": "app-1",
                                "name": "test-app-1",
                                "ingresses": [],
                                "deployments": {
                                  "nodes": []
                                },
                                "image": {
                                  "name": "test-app-1",
                                  "tag": "1.0.0",
                                  "vulnerabilities": {
                                    "pageInfo": {
                                      "hasNextPage": false,
                                      "endCursor": null
                                    },
                                    "nodes": []
                                  }
                                }
                              }
                            ]
                          }
                        }
                      }
                    }
                """
                            }

                            2 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "applications": {
                            "pageInfo": {
                              "hasNextPage": false,
                              "endCursor": null
                            },
                            "nodes": [
                              {
                                "id": "app-2",
                                "name": "test-app-2",
                                "ingresses": [],
                                "deployments": {
                                  "nodes": []
                                },
                                "image": {
                                  "name": "test-app-2",
                                  "tag": "1.0.0",
                                  "vulnerabilities": {
                                    "pageInfo": {
                                      "hasNextPage": false,
                                      "endCursor": null
                                    },
                                    "nodes": []
                                  }
                                }
                              }
                            ]
                          }
                        }
                      }
                    }
                """
                            }

                            3 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "jobs": {
                            "pageInfo": {
                              "hasNextPage": false,
                              "endCursor": null
                            },
                            "nodes": []
                          }
                        }
                      }
                    }
                """
                            }

                            else -> {
                                "{}"
                            }
                        }

                    respond(
                        content = ByteReadChannel(responseJson.trimIndent()),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            assertEquals(3, requestCount, "Should make paginated request for apps and one request for jobs")
            assertEquals(
                2,
                response.teams
                    .first()
                    .workloads.size,
                "Should have collected both apps from pagination",
            )
        }

    @Test
    fun `should handle vulnerability pagination within workload`() =
        runTest {
            var requestCount = 0
            val mockEngine =
                MockEngine { request ->
                    requestCount++
                    val responseJson =
                        when {
                            requestCount == 1 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "applications": {
                            "pageInfo": {
                              "hasNextPage": false,
                              "endCursor": null
                            },
                            "nodes": [
                              {
                                "id": "app-1",
                                "name": "test-app",
                                "ingresses": [],
                                "deployments": {
                                  "nodes": []
                                },
                                "image": {
                                  "name": "test-app",
                                  "tag": "1.0.0",
                                  "vulnerabilities": {
                                    "pageInfo": {
                                      "hasNextPage": true,
                                      "endCursor": "vuln-cursor-1"
                                    },
                                    "nodes": [
                                      {
                                        "identifier": "CVE-2024-0001",
                                        "description": "First vuln",
                                        "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                                        "severity": "HIGH",
                                        "package": "test-package-1",
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
                    }
                """
                            }

                            requestCount == 2 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "applications": {
                            "pageInfo": {
                              "hasNextPage": false,
                              "endCursor": null
                            },
                            "nodes": [
                              {
                                "id": "app-1",
                                "name": "test-app",
                                "ingresses": [],
                                "deployments": {
                                  "nodes": []
                                },
                                "image": {
                                  "name": "test-app",
                                  "tag": "1.0.0",
                                  "vulnerabilities": {
                                    "pageInfo": {
                                      "hasNextPage": false,
                                      "endCursor": null
                                    },
                                    "nodes": [
                                      {
                                        "identifier": "CVE-2024-0002",
                                        "description": "Second vuln",
                                        "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0002",
                                        "severity": "MEDIUM",
                                        "package": "test-package-2",
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
                    }
                """
                            }

                            requestCount == 3 -> {
                                """
                    {
                      "data": {
                        "team": {
                          "slug": "test-team",
                          "jobs": {
                            "pageInfo": {
                              "hasNextPage": false,
                              "endCursor": null
                            },
                            "nodes": []
                          }
                        }
                      }
                    }
                """
                            }

                            else -> {
                                "{}"
                            }
                        }

                    respond(
                        content = ByteReadChannel(responseJson.trimIndent()),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            assertEquals(3, requestCount, "Should make paginated requests for vulnerabilities plus jobs request")
            val workload =
                response.teams
                    .first()
                    .workloads
                    .first()
            assertEquals(2, workload.vulnerabilities.size, "Should have collected all vulnerabilities from pages")
        }

    @Test
    fun `should merge applications and jobs for team`() =
        runTest {
            var requestCount = 0
            val mockEngine =
                MockEngine { request ->
                    requestCount++
                    val responseJson =
                        if (requestCount == 1) {
                            """
                {
                  "data": {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "app-1",
                            "name": "test-app",
                            "ingresses": [],
                            "deployments": {
                              "nodes": []
                            },
                            "image": {
                              "name": "test-app",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": []
                              }
                            }
                          }
                        ]
                      }
                    }
                  }
                }
                """
                        } else {
                            """
                {
                  "data": {
                    "team": {
                      "slug": "test-team",
                      "jobs": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "job-1",
                            "name": "test-job",
                            "deployments": {
                              "nodes": []
                            },
                            "image": {
                              "name": "test-job",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": []
                              }
                            }
                          }
                        ]
                      }
                    }
                  }
                }
                """
                        }

                    respond(
                        content = ByteReadChannel(responseJson.trimIndent()),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            assertEquals(2, requestCount, "Should make separate requests for applications and jobs")
            val workloads = response.teams.first().workloads
            assertEquals(2, workloads.size, "Should have both app and job")
            assertEquals("app", workloads[0].workloadType)
            assertEquals("job", workloads[1].workloadType)
        }

    @Test
    fun `should handle suppressed vulnerabilities`() =
        runTest {
            val mockEngine =
                MockEngine { request ->
                    respond(
                        content =
                            ByteReadChannel(
                                """
                                {
                                  "data": {
                                    "team": {
                                      "slug": "test-team",
                                      "applications": {
                                        "pageInfo": {
                                          "hasNextPage": false,
                                          "endCursor": null
                                        },
                                        "nodes": [
                                          {
                                            "id": "app-1",
                                            "name": "test-app",
                                            "ingresses": [],
                                            "deployments": {
                                              "nodes": []
                                            },
                                            "image": {
                                              "name": "test-app",
                                              "tag": "1.0.0",
                                              "vulnerabilities": {
                                                "pageInfo": {
                                                  "hasNextPage": false,
                                                  "endCursor": null
                                                },
                                                "nodes": [
                                                  {
                                                    "identifier": "CVE-2024-1234",
                                                    "description": "Suppressed vulnerability",
                                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                                                    "severity": "HIGH",
                                                    "package": "test-package",
                                                    "suppression": {
                                                      "state": "SUPPRESSED"
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
                                """.trimIndent(),
                            ),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            val vuln =
                response.teams
                    .first()
                    .workloads
                    .first()
                    .vulnerabilities
                    .first()
            assertTrue(vuln.suppressed, "Vulnerability should be marked as suppressed")
        }

    @Test
    fun `should paginate vulnerabilities for multiple workloads in parallel`() =
        runTest {
            var requestCount = 0
            val mockEngine =
                MockEngine {
                    requestCount++
                    val responseJson =
                        when (requestCount) {
                            1 -> {
                                """
                    {
                      "data": { "team": { "slug": "test-team", "applications": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": [
                          { "id": "app-1", "name": "app-one", "ingresses": [], "deployments": { "nodes": [] },
                            "image": { "name": "app-one", "tag": "1.0.0", "vulnerabilities": {
                              "pageInfo": { "hasNextPage": true, "endCursor": "cursor-1" },
                              "nodes": [{ "identifier": "CVE-2024-0001", "description": "v1",
                                "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                                "severity": "HIGH", "package": "pkg", "suppression": null }]
                            }}},
                          { "id": "app-2", "name": "app-two", "ingresses": [], "deployments": { "nodes": [] },
                            "image": { "name": "app-two", "tag": "1.0.0", "vulnerabilities": {
                              "pageInfo": { "hasNextPage": true, "endCursor": "cursor-2" },
                              "nodes": [{ "identifier": "CVE-2024-0002", "description": "v2",
                                "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0002",
                                "severity": "MEDIUM", "package": "pkg", "suppression": null }]
                            }}}
                        ]
                      }}}
                    }
                    """
                            }

                            4 -> {
                                """{ "data": { "team": { "slug": "test-team",
                    "jobs": { "pageInfo": { "hasNextPage": false, "endCursor": null }, "nodes": [] }
                  }}}"""
                            }

                            else -> {
                                """
                    {
                      "data": { "team": { "slug": "test-team", "applications": {
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": [
                          { "id": "app-1", "name": "app-one", "ingresses": [], "deployments": { "nodes": [] },
                            "image": { "name": "app-one", "tag": "1.0.0", "vulnerabilities": {
                              "pageInfo": { "hasNextPage": false, "endCursor": null },
                              "nodes": [{ "identifier": "CVE-2024-0003", "description": "v3",
                                "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0003",
                                "severity": "LOW", "package": "pkg", "suppression": null }]
                            }}},
                          { "id": "app-2", "name": "app-two", "ingresses": [], "deployments": { "nodes": [] },
                            "image": { "name": "app-two", "tag": "1.0.0", "vulnerabilities": {
                              "pageInfo": { "hasNextPage": false, "endCursor": null },
                              "nodes": [{ "identifier": "CVE-2024-0004", "description": "v4",
                                "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2024-0004",
                                "severity": "LOW", "package": "pkg", "suppression": null }]
                            }}}
                        ]
                      }}}
                    }
                    """
                            }
                        }
                    respond(
                        content = ByteReadChannel(responseJson.trimIndent()),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

            assertNotNull(response)
            val workloads = response.teams.first().workloads
            assertEquals(2, workloads.size)
            val app1Vulns =
                workloads
                    .first { it.name == "app-one" }
                    .vulnerabilities
                    .map { it.identifier }
                    .toSet()
            val app2Vulns =
                workloads
                    .first { it.name == "app-two" }
                    .vulnerabilities
                    .map { it.identifier }
                    .toSet()
            assertEquals(setOf("CVE-2024-0001", "CVE-2024-0003"), app1Vulns)
            assertEquals(setOf("CVE-2024-0002", "CVE-2024-0004"), app2Vulns)
        }

    @Test
    fun `should not exceed concurrency limit of 4 when paginating team workloads`() =
        runTest {
            val inFlight = AtomicInteger(0)
            val peakConcurrency = AtomicInteger(0)

            // Build initial apps response: 8 workloads, each needing one more vuln page
            fun workloadNode(
                id: Int,
                hasNextPage: Boolean,
                cursor: String?,
            ) = """
            { "id": "app-$id", "name": "app-$id", "ingresses": [], "deployments": { "nodes": [] },
              "image": { "name": "app-$id", "tag": "1.0.0", "vulnerabilities": {
                "pageInfo": { "hasNextPage": $hasNextPage, "endCursor": ${if (cursor != null) "\"$cursor\"" else "null"} },
                "nodes": [{ "identifier": "CVE-000$id", "description": "v", "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-000$id", "severity": "HIGH", "package": "pkg", "suppression": null }]
              }}}
        """
            val appsNodes = (1..8).joinToString(",") { workloadNode(it, true, "cursor-$it") }
            val initialResponse = """{ "data": { "team": { "slug": "t", "applications": {
            "pageInfo": { "hasNextPage": false, "endCursor": null }, "nodes": [$appsNodes] } } } }"""

            val jobsResponse = """{ "data": { "team": { "slug": "t",
            "jobs": { "pageInfo": { "hasNextPage": false, "endCursor": null }, "nodes": [] } } } }"""

            var requestCount = 0
            val mockEngine =
                MockEngine {
                    val reqNum = ++requestCount
                    when {
                        reqNum == 1 -> {
                            respond(
                                content = ByteReadChannel(initialResponse),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json"),
                            )
                        }

                        reqNum == 10 -> {
                            respond( // jobs query (1 initial + 8 pagination + 1 jobs)
                                content = ByteReadChannel(jobsResponse),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json"),
                            )
                        }

                        else -> {
                            // Pagination request — track concurrency, simulate latency
                            val current = inFlight.incrementAndGet()
                            peakConcurrency.getAndUpdate { maxOf(it, current) }
                            delay(100) // yields so other coroutines can interleave
                            inFlight.decrementAndGet()
                            val appId = reqNum - 1 // approximate
                            respond(
                                content =
                                    ByteReadChannel(
                                        """{ "data": { "team": { "slug": "t", "applications": {
                            "pageInfo": { "hasNextPage": false, "endCursor": null },
                            "nodes": [{ "id": "app-$appId", "name": "app-$appId", "ingresses": [], "deployments": { "nodes": [] },
                              "image": { "name": "app-$appId", "tag": "1.0.0", "vulnerabilities": {
                                "pageInfo": { "hasNextPage": false, "endCursor": null },
                                "nodes": [] } } }] } } } }""",
                                    ),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json"),
                            )
                        }
                    }
                }

            val httpClient = createTestHttpClient(mockEngine)
            val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

            naisApiClient.getVulnerabilitiesForTeam("t")

            assertEquals(8, requestCount - 2, "Should have made one pagination request per workload")
            assertTrue(peakConcurrency.get() <= 4, "Peak concurrency was ${peakConcurrency.get()}, expected <= 4")
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
                    },
                )
            }
        }
}
