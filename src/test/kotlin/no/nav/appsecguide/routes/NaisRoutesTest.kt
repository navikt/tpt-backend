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

    @Test
    fun `should return team ingresses when team exists and authenticated`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = true)
            )
        }
        val response = client.get("/nais/teams/appsec/ingresses") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(json["data"])
    }

    @Test
    fun `should return unauthorized when no token provided`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/nais/teams/appsec/ingresses")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return bad request when teamSlug is missing`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123")
            )
        }
        val response = client.get("/nais/teams//ingresses") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `should return error when GraphQL fails`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = false)
            )
        }
        val response = client.get("/nais/teams/appsec/ingresses") {
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
        val response = client.get("/nais/applications/user") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(json["data"])
        val user = json["data"]?.jsonObject?.get("user")?.jsonObject
        assertNotNull(user)
        val teams = user["teams"]?.jsonObject?.get("nodes")?.jsonArray
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
        val response = client.get("/nais/applications/user") {
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
        val response = client.get("/nais/applications/user")
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
        val response = client.get("/nais/applications/user") {
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

            val response1 = client.get("/nais/applications/user") {
                bearerAuth("valid-token")
            }
            assertEquals(HttpStatusCode.OK, response1.status)

            val json1 = Json.parseToJsonElement(response1.bodyAsText()).jsonObject
            assertNotNull(json1["data"])
            val user1 = json1["data"]?.jsonObject?.get("user")?.jsonObject
            assertNotNull(user1)
            val teams1 = user1["teams"]?.jsonObject?.get("nodes")?.jsonArray
            assertNotNull(teams1)
            val team1Slug = teams1[0].jsonObject["team"]?.jsonObject?.get("slug")?.jsonPrimitive?.content
            val app1Name = teams1[0].jsonObject["team"]?.jsonObject?.get("applications")?.jsonObject
                ?.get("edges")?.jsonArray?.get(0)?.jsonObject?.get("node")?.jsonObject?.get("name")?.jsonPrimitive?.content

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

            val response2 = client.get("/nais/applications/user") {
                bearerAuth("valid-token")
            }
            assertEquals(HttpStatusCode.OK, response2.status)

            val json2 = Json.parseToJsonElement(response2.bodyAsText()).jsonObject
            assertNotNull(json2["data"])
            val user2 = json2["data"]?.jsonObject?.get("user")?.jsonObject
            assertNotNull(user2)
            val teams2 = user2["teams"]?.jsonObject?.get("nodes")?.jsonArray
            assertNotNull(teams2)
            val team2Slug = teams2[0].jsonObject["team"]?.jsonObject?.get("slug")?.jsonPrimitive?.content
            val app2Name = teams2[0].jsonObject["team"]?.jsonObject?.get("applications")?.jsonObject
                ?.get("edges")?.jsonArray?.get(0)?.jsonObject?.get("node")?.jsonObject?.get("name")?.jsonPrimitive?.content

            assertEquals("team-user2", team2Slug)
            assertEquals("app-user2", app2Name)

            assertNotEquals("team-user1", team2Slug)
            assertNotEquals("app-user1", app2Name)
        }
    }
}

