package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import no.nav.tpt.domain.ProblemDetail
import no.nav.tpt.infrastructure.auth.IntrospectionResponse
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json

class AdminRoutesTest {

    private class AdminMockTokenIntrospectionService : TokenIntrospectionService {
        override suspend fun introspect(token: String): IntrospectionResponse {
            return when (token) {
                "valid_admin_token" -> {
                    val claims = mutableMapOf<String, Any>(
                        "preferred_username" to JsonPrimitive("admin@nav.no"),
                        "groups" to JsonArray(listOf(JsonPrimitive("admin-group-1")))
                    )
                    IntrospectionResponse(active = true, claims = claims as Map<String, kotlinx.serialization.json.JsonElement>)
                }
                "valid_non_admin_token" -> {
                    val claims = mutableMapOf<String, Any>(
                        "preferred_username" to JsonPrimitive("user@nav.no"),
                        "groups" to JsonArray(listOf(JsonPrimitive("other-group")))
                    )
                    IntrospectionResponse(active = true, claims = claims as Map<String, kotlinx.serialization.json.JsonElement>)
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
}
