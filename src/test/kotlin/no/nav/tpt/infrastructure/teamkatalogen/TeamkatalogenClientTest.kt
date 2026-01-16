package no.nav.tpt.infrastructure.teamkatalogen

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class TeamkatalogenClientTest {

    @Test
    fun `should fetch membership by email`() = runBlocking {
        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/member/membership/byUserEmail") -> {
                    val email = request.url.parameters["email"]
                    assertEquals("test@nav.no", email)

                    respond(
                        content = """
                        {
                          "teams": [
                            {
                              "naisTeams": [
                                "appsec-a",
                                "appsec-b"
                              ]
                            },
                            {
                              "naisTeams": [
                                "appsec-c"
                              ]
                            }
                          ]
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> error("Unhandled ${request.url}")
            }
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

        val client = TeamkatalogenClient(httpClient, "http://test-teamkatalogen")
        val result = client.getMembershipByEmail("test@nav.no")

        assertEquals(3, result.naisTeams.size)
        assertEquals("appsec-a", result.naisTeams[0])
        assertEquals("appsec-b", result.naisTeams[1])
        assertEquals("appsec-c", result.naisTeams[2])
    }
}

