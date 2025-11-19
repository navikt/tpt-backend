package no.nav.appsecguide.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import kotlin.test.*
import no.nav.appsecguide.infrastructure.auth.MockTokenIntrospectionService
import no.nav.appsecguide.plugins.testModule

class UserRoutesTest {

    @Test
    fun `should return unauthorized when no token provided`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/me")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return unauthorized when invalid token provided`() = testApplication {
        application {
            testModule(MockTokenIntrospectionService(shouldSucceed = false))
        }
        val response = client.get("/me") {
            bearerAuth("invalid-token")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return NAVident when valid token provided`() = testApplication {
        application {
            testModule(MockTokenIntrospectionService(shouldSucceed = true, navIdent = "test123"))
        }
        val response = client.get("/me") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("test123", json["navIdent"]?.jsonPrimitive?.content)
    }

    @Test
    fun `should return NAVident and preferred_username when valid token provided`() = testApplication {
        application {
            testModule(MockTokenIntrospectionService(
                shouldSucceed = true,
                navIdent = "test123",
                preferredUsername = "test.user@nav.no"
            ))
        }
        val response = client.get("/me") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("test123", json["navIdent"]?.jsonPrimitive?.content)
        assertEquals("test.user@nav.no", json["preferredUsername"]?.jsonPrimitive?.content)
    }
}

