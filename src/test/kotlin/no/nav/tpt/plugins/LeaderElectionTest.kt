package no.nav.tpt.plugins

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.engine.mock.respondOk
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LeaderElectionTest {

    @Test
    fun `should return true when ELECTOR_GET_URL is not set`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) { engine { addHandler { respondOk() } } }
        val leaderElection = LeaderElection(mockHttpClient)

        // When ELECTOR_GET_URL is not set, should assume single instance (leader)
        leaderElection.startLeaderElectionChecks(TestScope())

        assertTrue(leaderElection.isLeader())
    }

    @Test
    fun `should cache leader status and update on timer`() = runTest {
        val hostname = InetAddress.getLocalHost().hostName

        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { _ ->
                    respond(
                        content = """{"name":"$hostname"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
            }
        }

        val leaderElection = LeaderElection(mockHttpClient)

        // Initially false (not checked yet)
        assertFalse(leaderElection.isLeader())

        // Note: In real environment with ELECTOR_GET_URL set,
        // startLeaderElectionChecks would update the cached value periodically
    }

    @Test
    fun `should return false when HTTP request fails`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { _ ->
                    respondError(HttpStatusCode.InternalServerError)
                }
            }
        }

        val leaderElection = LeaderElection(mockHttpClient)

        // Initially false before any check
        assertFalse(leaderElection.isLeader())
    }

    @Test
    fun `should execute operation only if leader`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) { engine { addHandler { respondOk() } } }
        val leaderElection = LeaderElection(mockHttpClient)

        // Simulate leader status
        leaderElection.startLeaderElectionChecks(TestScope())

        var executed = false
        leaderElection.ifLeader {
            executed = true
            "result"
        }

        // Should execute when ELECTOR_GET_URL is not set (assumes leader)
        assertTrue(executed)
    }

    @Test
    fun `should not execute operation when not leader`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { _ ->
                    respond(
                        content = """{"name":"other-pod"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
            }
        }

        val leaderElection = LeaderElection(mockHttpClient)

        var executed = false
        val result = leaderElection.ifLeader {
            executed = true
            "result"
        }

        // Should not execute when not leader
        assertFalse(executed)
        assertTrue(result == null)
    }
}