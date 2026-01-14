package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GraphQLSchemaTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `NaisApiClient should successfully fetch and deserialize vulnerabilities for user with all required fields`() = kotlinx.coroutines.test.runTest {
        val mockJsonResponse = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": "navikt/test-app",
                                  "environmentName": "production"
                                }
                              ]
                            },
                            "image": {
                              "name": "test-image",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-1234",
                                    "description": "Test vulnerability description",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                                    "severity": "HIGH",
                                    "package": "pkg:golang/example.com/test-package@v1.0.0",
                                    "suppression": {
                                      "state": "NOT_SUPPRESSED"
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
                ]
              }
            }
          }
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals(request.body.contentType?.match(ContentType.Application.Json), true)

            respond(
                content = mockJsonResponse,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }

        val client = NaisApiClient(httpClient, "https://test.api", "test-token")
        val response = client.getVulnerabilitiesForUser("test@example.com")

        assertNotNull(response.data)
        val user = response.data?.user
        assertNotNull(user)
        val team = user.teams.nodes.firstOrNull()
        assertNotNull(team)
        assertEquals("test-team", team.team.slug)

        val workload = team.team.applications?.nodes?.firstOrNull()
        assertNotNull(workload)
        assertEquals("workload-1", workload.id)
        assertEquals("test-app", workload.name)
        assertEquals("navikt/test-app", workload.deployments.nodes.firstOrNull()?.repository)
        assertEquals("production", workload.deployments.nodes.firstOrNull()?.environmentName)

        val vulnerability = workload.image?.vulnerabilities?.nodes?.firstOrNull()
        assertNotNull(vulnerability)
        assertEquals("CVE-2023-1234", vulnerability.identifier)
        assertEquals("Test vulnerability description", vulnerability.description)
        assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2023-1234", vulnerability.vulnerabilityDetailsLink)
        assertEquals("HIGH", vulnerability.severity)
        assertEquals("pkg:golang/example.com/test-package@v1.0.0", vulnerability.packageName)
        assertEquals("NOT_SUPPRESSED", vulnerability.suppression?.state)

        httpClient.close()
    }

    @Test
    fun `should deserialize VulnerabilitiesForUser response with all required fields`() {
        val jsonResponse = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": "navikt/test-app",
                                  "environmentName": "production"
                                }
                              ]
                            },
                            "image": {
                              "name": "test-image",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-1234",
                                    "description": "Test vulnerability description",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                                    "severity": "HIGH",
                                    "package": "pkg:golang/example.com/test-package@v1.0.0",
                                    "suppression": {
                                      "state": "NOT_SUPPRESSED"
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
                ]
              }
            }
          }
        }
        """.trimIndent()

        val response = json.decodeFromString(WorkloadVulnerabilitiesResponse.serializer(), jsonResponse)

        assertNotNull(response.data)
        assertNotNull(response.data?.user)
        val team = response.data?.user?.teams?.nodes?.firstOrNull()
        assertNotNull(team)
        assertEquals("test-team", team.team.slug)

        val workload = team.team.applications?.nodes?.firstOrNull()
        assertNotNull(workload)
        assertEquals("workload-1", workload.id)
        assertEquals("test-app", workload.name)
        assertEquals("navikt/test-app", workload.deployments.nodes.firstOrNull()?.repository)
        assertEquals("production", workload.deployments.nodes.firstOrNull()?.environmentName)

        val vulnerability = workload.image?.vulnerabilities?.nodes?.firstOrNull()
        assertNotNull(vulnerability)
        assertEquals("CVE-2023-1234", vulnerability.identifier)
        assertEquals("Test vulnerability description", vulnerability.description)
        assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2023-1234", vulnerability.vulnerabilityDetailsLink)
        assertEquals("HIGH", vulnerability.severity)
        assertEquals("pkg:golang/example.com/test-package@v1.0.0", vulnerability.packageName)
        assertEquals("NOT_SUPPRESSED", vulnerability.suppression?.state)
    }

    @Test
    fun `NaisApiClient should fail when deployments field is missing from API response`() = kotlinx.coroutines.test.runTest {
        val mockJsonResponseMissingDeployments = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "image": {
                              "name": "test-image",
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
                ]
              }
            }
          }
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = mockJsonResponseMissingDeployments,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }

        val client = NaisApiClient(httpClient, "https://test.api", "test-token")

        try {
            client.getVulnerabilitiesForUser("test@example.com")
            throw AssertionError("Expected deserialization to fail due to missing deployments field")
        } catch (e: Exception) {
            val containsDeployments = e.message?.contains("deployments") == true || e.cause?.message?.contains("deployments") == true
            assertTrue(containsDeployments, "Exception should mention missing 'deployments' field, but got: ${e.message}")
        } finally {
            httpClient.close()
        }
    }

    @Test
    fun `should fail when deployments field is missing from VulnerabilitiesForUser response`() {
        val jsonResponseMissingDeployments = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "image": {
                              "name": "test-image",
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
                ]
              }
            }
          }
        }
        """.trimIndent()

        try {
            json.decodeFromString(WorkloadVulnerabilitiesResponse.serializer(), jsonResponseMissingDeployments)
            throw AssertionError("Expected deserialization to fail due to missing deployments field")
        } catch (e: Exception) {
            assert(e.message?.contains("deployments") == true) {
                "Exception should mention missing 'deployments' field"
            }
        }
    }

    @Test
    fun `NaisApiClient should fail when package field is missing from vulnerability in API response`() = kotlinx.coroutines.test.runTest {
        val mockJsonResponseMissingPackage = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": null,
                                  "environmentName": null
                                }
                              ]
                            },
                            "image": {
                              "name": "test-image",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-1234",
                                    "description": "Test vulnerability",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                                    "severity": "HIGH",
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

        val mockEngine = MockEngine { request ->
            respond(
                content = mockJsonResponseMissingPackage,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }

        val client = NaisApiClient(httpClient, "https://test.api", "test-token")

        try {
            client.getVulnerabilitiesForUser("test@example.com")
            throw AssertionError("Expected deserialization to fail due to missing package field")
        } catch (e: Exception) {
            val containsPackage = e.message?.contains("package") == true || e.cause?.message?.contains("package") == true
            assertTrue(containsPackage, "Exception should mention missing 'package' field, but got: ${e.message}")
        } finally {
            httpClient.close()
        }
    }

    @Test
    fun `should fail when package field is missing from vulnerability in VulnerabilitiesForUser response`() {
        val jsonResponseMissingPackage = """
        {
          "data": {
            "user": {
              "teams": {
                "pageInfo": {
                  "hasNextPage": false,
                  "endCursor": null
                },
                "nodes": [
                  {
                    "team": {
                      "slug": "test-team",
                      "applications": {
                        "pageInfo": {
                          "hasNextPage": false,
                          "endCursor": null
                        },
                        "nodes": [
                          {
                            "id": "workload-1",
                            "name": "test-app",
                            "deployments": {
                              "nodes": [
                                {
                                  "repository": null,
                                  "environmentName": null
                                }
                              ]
                            },
                            "image": {
                              "name": "test-image",
                              "tag": "1.0.0",
                              "vulnerabilities": {
                                "pageInfo": {
                                  "hasNextPage": false,
                                  "endCursor": null
                                },
                                "nodes": [
                                  {
                                    "identifier": "CVE-2023-1234",
                                    "description": "Test vulnerability",
                                    "vulnerabilityDetailsLink": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                                    "severity": "HIGH",
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

        try {
            json.decodeFromString(WorkloadVulnerabilitiesResponse.serializer(), jsonResponseMissingPackage)
            throw AssertionError("Expected deserialization to fail due to missing package field")
        } catch (e: Exception) {
            assert(e.message?.contains("package") == true) {
                "Exception should mention missing 'package' field"
            }
        }
    }
}

