package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NaisApiClientTeamVulnerabilitiesTest {

    @Test
    fun `should parse team vulnerabilities response correctly`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
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
                    """.trimIndent()
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

        assertNotNull(response)
        assertEquals(1, response.teams.size)
        assertEquals("test-team", response.teams.first().teamSlug)
        assertEquals(1, response.teams.first().workloads.size)
        val workload = response.teams.first().workloads.first()
        assertEquals("test-app", workload.name)
        assertEquals("app", workload.workloadType)
        assertEquals(1, workload.vulnerabilities.size)
        assertEquals("CVE-2024-1234", workload.vulnerabilities.first().identifier)
        assertEquals("HIGH", workload.vulnerabilities.first().severity)
    }

    @Test
    fun `should throw exception when team not found`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
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
                    """.trimIndent()
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val exception = kotlin.runCatching {
            naisApiClient.getVulnerabilitiesForTeam("nonexistent-team")
        }.exceptionOrNull()

        assertNotNull(exception)
        assertTrue(exception.message?.contains("GraphQL errors") == true)
        assertTrue(exception.message?.contains("Team not found") == true)
    }

    @Test
    fun `should handle team with no applications or jobs`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
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
                    """.trimIndent()
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getVulnerabilitiesForTeam("empty-team")

        assertNotNull(response)
        assertEquals("empty-team", response.teams.first().teamSlug)
        assertEquals(0, response.teams.first().workloads.size)
    }

    @Test
    fun `should handle workload pagination correctly`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val responseJson = when (requestCount) {
                1 -> """
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
                2 -> """
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
                3 -> """
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
                else -> "{}"
            }

            respond(
                content = ByteReadChannel(responseJson.trimIndent()),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

        assertNotNull(response)
        assertEquals(3, requestCount, "Should make paginated request for apps and one request for jobs")
        assertEquals(2, response.teams.first().workloads.size, "Should have collected both apps from pagination")
    }

    @Test
    fun `should handle vulnerability pagination within workload`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val responseJson = when {
                requestCount == 1 -> """
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
                requestCount == 2 -> """
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
                requestCount == 3 -> """
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
                else -> "{}"
            }

            respond(
                content = ByteReadChannel(responseJson.trimIndent()),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

        assertNotNull(response)
        assertEquals(3, requestCount, "Should make paginated requests for vulnerabilities plus jobs request")
        val workload = response.teams.first().workloads.first()
        assertEquals(2, workload.vulnerabilities.size, "Should have collected all vulnerabilities from pages")
    }

    @Test
    fun `should merge applications and jobs for team`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val responseJson = if (requestCount == 1) {
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
                headers = headersOf(HttpHeaders.ContentType, "application/json")
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
    fun `should handle suppressed vulnerabilities`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
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
                    """.trimIndent()
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = createTestHttpClient(mockEngine)
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getVulnerabilitiesForTeam("test-team")

        assertNotNull(response)
        val vuln = response.teams.first().workloads.first().vulnerabilities.first()
        assertTrue(vuln.suppressed, "Vulnerability should be marked as suppressed")
    }

    private fun createTestHttpClient(mockEngine: MockEngine) = HttpClient(mockEngine) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
                explicitNulls = false
                coerceInputValues = true
            })
        }
    }
}
