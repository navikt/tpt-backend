package no.nav.tpt.routes

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import no.nav.tpt.domain.ProblemDetail
import no.nav.tpt.infrastructure.auth.IntrospectionResponse
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdminRoutesTest {

    private class AdminMockTokenIntrospectionService : TokenIntrospectionService {
        override suspend fun introspect(token: String): IntrospectionResponse {
            return when (token) {
                "valid_admin_token" -> {
                    val claims = mutableMapOf(
                        "preferred_username" to JsonPrimitive("admin@nav.no"),
                        "groups" to JsonArray(listOf(JsonPrimitive("admin-group-1")))
                    )
                    IntrospectionResponse(active = true, claims = claims)
                }
                "valid_non_admin_token" -> {
                    val claims = mutableMapOf(
                        "preferred_username" to JsonPrimitive("user@nav.no"),
                        "groups" to JsonArray(listOf(JsonPrimitive("other-group")))
                    )
                    IntrospectionResponse(active = true, claims = claims)
                }
                else -> IntrospectionResponse(active = false, claims = emptyMap())
            }
        }
    }

    @Test
    fun `should return OK for user with admin group`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = AdminMockTokenIntrospectionService(),
                adminAuthorizationService = no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl("admin-group-1")
            )
        }
        
        val response = client.get("/admin/status") {
            header(HttpHeaders.Authorization, "Bearer valid_admin_token")
        }
        
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyAsText().contains("\"status\":\"OK\"") || response.bodyAsText().contains("\"status\": \"OK\""))
    }

    @Test
    fun `should return 401 for missing token`() = testApplication {
        application {
            testModule()
        }
        
        val response = client.get("/admin/status")
        
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 403 for user without admin group`() = testApplication {
        application {
            testModule(tokenIntrospectionService = AdminMockTokenIntrospectionService())
        }
        
        val response = client.get("/admin/status") {
            header(HttpHeaders.Authorization, "Bearer valid_non_admin_token")
        }
        
        assertEquals(HttpStatusCode.Forbidden, response.status)
    }

    @Test
    fun `should return vulnerabilities for team when admin token is provided`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = AdminMockTokenIntrospectionService(),
                adminAuthorizationService = no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl("admin-group-1")
            )
        }

        val response = client.get("/admin/vulnerabilities/team/team-appsec") {
            header(HttpHeaders.Authorization, "Bearer valid_admin_token")
        }

        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `should return 500 Problem Detail when admin team repository read fails`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = AdminMockTokenIntrospectionService(),
                adminAuthorizationService = no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl(
                    "admin-group-1",
                ),
                vulnerabilityRepository = MockVulnerabilityRepository(throwException = true),
            )
        }

        val response = client.get("/admin/vulnerabilities/team/team-appsec") {
            header(HttpHeaders.Authorization, "Bearer valid_admin_token")
        }

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertEquals(ContentType("application", "problem+json"), response.contentType()?.withoutParameters())

        val problem = Json.decodeFromString<ProblemDetail>(response.bodyAsText())
        assertEquals("about:blank", problem.type)
        assertEquals("Internal Server Error", problem.title)
        assertEquals(500, problem.status)
        assertEquals("/admin/vulnerabilities/team/team-appsec", problem.instance)
    }

    @Test
    fun `should return 403 for non-admin user on team vulnerabilities endpoint`() = testApplication {
        application {
            testModule(tokenIntrospectionService = AdminMockTokenIntrospectionService())
        }

        val response = client.get("/admin/vulnerabilities/team/team-appsec") {
            header(HttpHeaders.Authorization, "Bearer valid_non_admin_token")
        }

        assertEquals(HttpStatusCode.Forbidden, response.status)
    }

    @Test
    fun `should return 401 for missing token on team vulnerabilities endpoint`() = testApplication {
        application {
            testModule()
        }

        val response = client.get("/admin/vulnerabilities/team/team-appsec")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }
}
