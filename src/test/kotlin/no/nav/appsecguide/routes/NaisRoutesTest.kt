package no.nav.appsecguide.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import kotlin.test.*
import no.nav.appsecguide.infrastructure.auth.MockTokenIntrospectionService
import no.nav.appsecguide.infrastructure.nais.MockNaisApiService
import no.nav.appsecguide.plugins.testModule

class NaisRoutesTest {

    private val teamTestIngress = "/applications/appsec"
    private val userTestIngress = "/applications/user"

    @Test
    fun `should return team applications when team exists and authenticated`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = true)
            )
        }
        val response = client.get(teamTestIngress) {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(json["team"])
        assertNotNull(json["applications"])
        val applications = json["applications"]?.jsonArray
        assertTrue(applications?.isNotEmpty() ?: false)
    }

    @Test
    fun `should return unauthorized when no token provided`() = testApplication {
        application {
            testModule()
        }
        val response = client.get(teamTestIngress)
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return not found when route does not match`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123")
            )
        }
        val response = client.get("/applications/") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `should return error when GraphQL fails for team applications`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = false)
            )
        }
        val response = client.get(teamTestIngress) {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.BadGateway, response.status)
    }

    @Test
    fun `should return user applications when authenticated with preferred username`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(
                    shouldSucceed = true,
                    navIdent = "user123",
                    preferredUsername = "user123@nav.no"
                ),
                naisApiService = MockNaisApiService(shouldSucceed = true)
            )
        }
        val response = client.get(userTestIngress) {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(json["teams"])
        val teams = json["teams"]?.jsonArray
        assertNotNull(teams)
        assertTrue(teams.size > 0)
    }

    @Test
    fun `should return bad request when preferred username is missing`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(
                    shouldSucceed = true,
                    navIdent = "user123",
                    preferredUsername = null
                ),
                naisApiService = MockNaisApiService(shouldSucceed = true)
            )
        }
        val response = client.get(userTestIngress) {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("Bad Request", json["title"]?.jsonPrimitive?.content)
        assertTrue(json["detail"]?.jsonPrimitive?.content?.contains("preferred_username") ?: false)
    }

    @Test
    fun `should return unauthorized when no token provided for user applications`() = testApplication {
        application {
            testModule()
        }
        val response = client.get(userTestIngress)
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return error when GraphQL fails for user applications`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(
                    shouldSucceed = true,
                    navIdent = "user123",
                    preferredUsername = "user123@nav.no"
                ),
                naisApiService = MockNaisApiService(shouldSucceed = false)
            )
        }
        val response = client.get(userTestIngress) {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.BadGateway, response.status)
    }

    @Test
    fun `should return different results for different users`() {
        val mockService = MockNaisApiService(shouldSucceed = true)

        testApplication {
            application {
                testModule(
                    tokenIntrospectionService = MockTokenIntrospectionService(
                        shouldSucceed = true,
                        navIdent = "user1",
                        preferredUsername = "user1@nav.no"
                    ),
                    naisApiService = mockService
                )
            }

            val response1 = client.get(userTestIngress) {
                bearerAuth("valid-token")
            }
            assertEquals(HttpStatusCode.OK, response1.status)

            val json1 = Json.parseToJsonElement(response1.bodyAsText()).jsonObject
            assertNotNull(json1["teams"])
            val teams1 = json1["teams"]?.jsonArray
            assertNotNull(teams1)
            assertTrue(teams1.isNotEmpty())
            val team1 = teams1[0].jsonObject
            assertNotNull(team1)
            val team1Slug = team1["team"]?.jsonPrimitive?.content
            val apps1 = team1["applications"]?.jsonArray
            assertNotNull(apps1)
            assertTrue(apps1.isNotEmpty())
            val app1Name = apps1[0].jsonObject["name"]?.jsonPrimitive?.content

            assertEquals("team-user1", team1Slug)
            assertEquals("app-user1", app1Name)
        }

        testApplication {
            application {
                testModule(
                    tokenIntrospectionService = MockTokenIntrospectionService(
                        shouldSucceed = true,
                        navIdent = "user2",
                        preferredUsername = "user2@nav.no"
                    ),
                    naisApiService = mockService
                )
            }

            val response2 = client.get(userTestIngress) {
                bearerAuth("valid-token")
            }
            assertEquals(HttpStatusCode.OK, response2.status)

            val json2 = Json.parseToJsonElement(response2.bodyAsText()).jsonObject
            assertNotNull(json2["teams"])
            val teams2 = json2["teams"]?.jsonArray
            assertNotNull(teams2)
            assertTrue(teams2.isNotEmpty())
            val team2 = teams2[0].jsonObject
            assertNotNull(team2)
            val team2Slug = team2["team"]?.jsonPrimitive?.content
            val apps2 = team2["applications"]?.jsonArray
            assertNotNull(apps2)
            assertTrue(apps2.isNotEmpty())
            val app2Name = apps2[0].jsonObject["name"]?.jsonPrimitive?.content

            assertEquals("team-user2", team2Slug)
            assertEquals("app-user2", app2Name)

            assertNotEquals("team-user1", team2Slug)
            assertNotEquals("app-user1", app2Name)
        }
    }
}

