package no.nav.tpt.routes

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import no.nav.tpt.infrastructure.auth.IntrospectionResponse
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.datacollector.DataCollectorRepositoryImpl
import no.nav.tpt.infrastructure.datacollector.DatacollectorRepository
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventLogRepository
import no.nav.tpt.plugins.testModule
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.BeforeAll
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@Testcontainers
class DataCollectorCallbackIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("test_db")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var gitHubRepository: GitHubRepository
        private lateinit var dataCollectorRepository: DatacollectorRepository
        private lateinit var sseEventLogRepository: SseEventLogRepository

        @JvmStatic
        @BeforeAll
        fun setUpClass() {
            val dataSource = HikariDataSource(HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            })
            Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate()

            val database = Database.connect(dataSource)
            gitHubRepository = GitHubRepositoryImpl(database)
            dataCollectorRepository = DataCollectorRepositoryImpl(database)
            sseEventLogRepository = SseEventLogRepository(database)
        }
    }

    private val dataCollectorToken = object : TokenIntrospectionService {
        override suspend fun introspect(token: String) = IntrospectionResponse(
            active = true,
            claims = mapOf(
                "idtyp" to JsonPrimitive("app"),
                "azp_name" to JsonPrimitive("dev-gcp:appsec:tpt-data-collector"),
            ),
        )
    }

    private fun repositoryPayload(nameWithOwner: String) = """
        {
          "nameWithOwner": "$nameWithOwner",
          "naisTeams": ["team-a", "team-b"],
          "unknownField": "ignored",
          "vulnerabilities": [
            {
              "severity": "CRITICAL",
              "identifiers": [
                {"value": "CVE-2024-9999", "type": "CVE"},
                {"value": "GHSA-abcd-efgh-ijkl", "type": "GHSA"}
              ],
              "dependencyScope": "RUNTIME",
              "dependabotUpdatePullRequestUrl": "https://github.com/org/repo/pull/42",
              "publishedAt": "2024-01-15T10:30:00Z",
              "cvssScore": 9.8,
              "summary": "Critical vulnerability in dependency",
              "packageEcosystem": "NPM",
              "packageName": "vulnerable-package"
            },
            {
              "severity": "LOW",
              "identifiers": [{"value": "CVE-2024-1111", "type": "CVE"}]
            }
          ]
        }
    """.trimIndent()

    private fun checksPayload(repoName: String, owner: String) = """
        {
          "repoName": "$repoName",
          "repoOwners": ["$owner"],
          "results": [
            {"type": "AllGood", "name": "branch-protection", "desc": "Branch protection", "severity": "HIGH", "whenChecked": "2026-01-01T10:00:00.123Z"},
            {"type": "NeedsWork", "name": "codeowners", "severity": "LOW", "whenChecked": "2026-01-01T10:00:00Z", "reasons": ["missing file", "no owners"]}
          ]
        }
    """.trimIndent()

    private fun postCallback(path: String, body: String) = testApplication {
        application {
            testModule(
                tokenIntrospectionService = dataCollectorToken,
                gitHubRepository = gitHubRepository,
                dataCollectorRepository = dataCollectorRepository,
                sseEventLogRepository = sseEventLogRepository,
            )
        }

        val response = client.post(path) {
            header(HttpHeaders.Authorization, "Bearer test-token")
            contentType(ContentType.Application.Json)
            setBody(body)
        }

        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun `should persist vulnerability data delivered by callback`() {
        val nameWithOwner = "navikt/callback-integration"
        postCallback("/callbacks/github/vulnerabilities", repositoryPayload(nameWithOwner))

        runBlocking {
            val repository = gitHubRepository.getRepository(nameWithOwner)
            assertNotNull(repository)
            assertEquals(listOf("team-a", "team-b"), repository.naisTeams)
            assertEquals(2, gitHubRepository.getVulnerabilities(nameWithOwner).size)
        }
    }

    @Test
    fun `should persist check results delivered by callback`() {
        val repoName = "navikt/check-callback-integration"
        postCallback("/callbacks/checks", checksPayload(repoName, "team-callback"))

        runBlocking {
            val results = dataCollectorRepository.allForOwner(listOf("team-callback"))[repoName]
            assertNotNull(results)
            assertEquals(listOf("branch-protection", "codeowners"), results.map { it.name }.sorted())
        }
    }

    @Test
    fun `should write sync signals to the SSE event log`() {
        val lastId = runBlocking { sseEventLogRepository.latestEventId() }

        postCallback("/callbacks/github/sync/started", """{"teams": ["team-a"], "timestamp": "2026-01-01T10:00:00Z"}""")
        postCallback("/callbacks/github/sync/complete", """{"teams": ["team-a"], "timestamp": "2026-01-01T10:05:00Z"}""")

        val events = runBlocking { sseEventLogRepository.eventsAfter(lastId).map { it.event } }
        assertEquals(
            listOf(
                SseEvent.GitHubVulnSyncStarted(listOf("team-a"), "2026-01-01T10:00:00Z"),
                SseEvent.GitHubVulnSyncComplete(listOf("team-a"), "2026-01-01T10:05:00Z"),
            ),
            events,
        )
    }
}
