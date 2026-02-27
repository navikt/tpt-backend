package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.remediation.RemediationException
import no.nav.tpt.domain.remediation.RemediationRequest
import no.nav.tpt.domain.remediation.RemediationService
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.plugins.remediationTestModule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private val validRequest = RemediationRequest(
    cveId = "CVE-2024-1234",
    workloadName = "my-app",
    environment = "production",
    packageName = "some-package",
    packageEcosystem = "npm"
)

private class MockRemediationService(
    private val chunks: List<String> = emptyList(),
    private val error: Exception? = null
) : RemediationService {
    override fun streamRemediation(request: RemediationRequest): Flow<String> = flow {
        error?.let { throw it }
        chunks.forEach { emit(it) }
    }
}

class RemediationRoutesTest {

    @Test
    fun `should return 503 when remediation service is not configured`() = testApplication {
        application { remediationTestModule(remediationService = null) }

        val response = client.post("/vulnerabilities/remediation") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(validRequest))
        }

        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
    }

    @Test
    fun `should send done event when stream completes successfully`() = testApplication {
        application {
            remediationTestModule(remediationService = MockRemediationService(chunks = listOf("Hello ", "world")))
        }

        val response = client.post("/vulnerabilities/remediation") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(validRequest))
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("event: done"), "Expected 'event: done' in SSE body but got: $body")
    }

    @Test
    fun `should send structured error event when AI service fails`() = testApplication {
        application {
            remediationTestModule(
                remediationService = MockRemediationService(
                    error = RemediationException.AiServiceException("Vertex AI returned 503")
                )
            )
        }

        val response = client.post("/vulnerabilities/remediation") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(validRequest))
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("event: error"), "Expected 'event: error' in SSE body but got: $body")
        assertTrue(body.contains("ai_service_error"), "Expected 'ai_service_error' code in SSE error data but got: $body")
    }

    @Test
    fun `should send structured error event when data fetch fails`() = testApplication {
        application {
            remediationTestModule(
                remediationService = MockRemediationService(
                    error = RemediationException.DataFetchException("NVD fetch failed")
                )
            )
        }

        val response = client.post("/vulnerabilities/remediation") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(validRequest))
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("event: error"), "Expected 'event: error' in SSE body but got: $body")
        assertTrue(body.contains("data_fetch_error"), "Expected 'data_fetch_error' code in SSE error data but got: $body")
    }
}
