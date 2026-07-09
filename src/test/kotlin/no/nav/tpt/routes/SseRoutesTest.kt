package no.nav.tpt.routes

import io.ktor.client.plugins.timeout
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals

class SseRoutesTest {

    @Test
    fun `should reject request without bearer token`() = testApplication {
        application { testModule() }

        val response = client.get("/events")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should reject request with invalid bearer token`() = testApplication {
        application {
            testModule(tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = false))
        }

        val response = client.get("/events") {
            header(HttpHeaders.Authorization, "Bearer invalid-token")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should accept authenticated request and return event-stream content type`() = testApplication {
        application { testModule() }

        val client = createClient {
            followRedirects = false
        }

        val response = client.prepareGet("/events") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            header(HttpHeaders.Accept, "text/event-stream")
            timeout { requestTimeoutMillis = 500 }
        }.execute { resp ->
            resp
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val contentType = response.headers[HttpHeaders.ContentType]
        assertEquals("text/event-stream", contentType?.substringBefore(";")?.trim())
    }
}
