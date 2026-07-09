package no.nav.tpt.routes

import io.ktor.client.plugins.timeout
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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

        val (status, contentType) = client.prepareGet("/events") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
            header(HttpHeaders.Accept, "text/event-stream")
            timeout { requestTimeoutMillis = 500 }
        }.execute { resp ->
            resp.status to resp.headers[HttpHeaders.ContentType]
        }

        assertEquals(HttpStatusCode.OK, status)
        assertEquals("text/event-stream", contentType?.substringBefore(";")?.trim())
    }

    // ---------------------------------------------------------------------------
    // Event relevance filtering (unit-level, no HTTP layer)
    // ---------------------------------------------------------------------------

    @Test
    fun `should consider TeamSyncStarted relevant only for matching team`() {
        val userTeams = setOf("team-alpha")
        val event = SseEvent.TeamSyncStarted("team-alpha", "2024-01-01T00:00:00Z")
        val irrelevant = SseEvent.TeamSyncStarted("team-beta", "2024-01-01T00:00:00Z")

        assertTrue(isSseEventRelevant(event, userTeams))
        assertFalse(isSseEventRelevant(irrelevant, userTeams))
    }

    @Test
    fun `should consider TeamSyncComplete relevant only for matching team`() {
        val userTeams = setOf("team-alpha")
        val event = SseEvent.TeamSyncComplete("team-alpha", "2024-01-01T00:00:00Z")
        val irrelevant = SseEvent.TeamSyncComplete("team-beta", "2024-01-01T00:00:00Z")

        assertTrue(isSseEventRelevant(event, userTeams))
        assertFalse(isSseEventRelevant(irrelevant, userTeams))
    }

    @Test
    fun `should consider GcveSyncComplete relevant for all users`() {
        val event = SseEvent.GcveSyncComplete(42, "2024-01-01T00:00:00Z")

        assertTrue(isSseEventRelevant(event, emptySet()))
        assertTrue(isSseEventRelevant(event, setOf("team-alpha")))
    }

    @Test
    fun `should handle user with multiple teams`() {
        val userTeams = setOf("team-alpha", "team-gamma")

        assertTrue(isSseEventRelevant(SseEvent.TeamSyncComplete("team-alpha", "t"), userTeams))
        assertTrue(isSseEventRelevant(SseEvent.TeamSyncComplete("team-gamma", "t"), userTeams))
        assertFalse(isSseEventRelevant(SseEvent.TeamSyncComplete("team-beta", "t"), userTeams))
    }

    private fun isSseEventRelevant(event: SseEvent, userTeamSlugs: Set<String>): Boolean =
        when (event) {
            is SseEvent.TeamSyncStarted -> event.teamSlug in userTeamSlugs
            is SseEvent.TeamSyncComplete -> event.teamSlug in userTeamSlugs
            is SseEvent.GcveSyncComplete -> true
        }
}
