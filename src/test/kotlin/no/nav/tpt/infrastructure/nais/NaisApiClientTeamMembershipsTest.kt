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

class NaisApiClientTeamMembershipsTest {

    @Test
    fun `should handle user not found error correctly`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
                    """
                    {
                      "errors": [
                        {
                          "message": "The specified user was not found.",
                          "path": ["user"]
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

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getTeamMembershipsForUser("notfound@external.com")

        assertTrue(response.isEmpty())
    }

    @Test
    fun `should return team memberships when user is found`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
                    """
                    {
                      "data": {
                        "user": {
                          "teams": {
                            "nodes": [
                              {
                                "team": {
                                  "slug": "team-a"
                                }
                              },
                              {
                                "team": {
                                  "slug": "team-b"
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

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getTeamMembershipsForUser("member@nav.no")

        assertEquals(2, response.size)
        assertEquals("team-a", response[0])
        assertEquals("team-b", response[1])
    }

    @Test
    fun `should return empty team list when user has no memberships`() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = ByteReadChannel(
                    """
                    {
                      "data": {
                        "user": {
                          "teams": {
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

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }
        val naisApiClient = NaisApiClient(httpClient, "https://api.nais.io", "test-token")

        val response = naisApiClient.getTeamMembershipsForUser("developer@nav.no")

        assertTrue(response.isEmpty())
    }
}
