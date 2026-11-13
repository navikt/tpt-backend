package no.nav.tpt.infrastructure.github.copilot

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.test.runTest
import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Testcontainers
class CopilotRemediationRepositoryImplTest {
    private val key = RemediationKey("navikt/app-a", "CVE-2026-0001", "lib-a")
    private val now = Instant.parse("2026-11-01T12:00:00Z")

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("copilot_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database
        private lateinit var repository: CopilotRemediationRepositoryImpl

        @JvmStatic
        @BeforeAll
        fun setUp() {
            postgresContainer.start()
            val dataSource = HikariDataSource(HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            })
            Flyway.configure().dataSource(dataSource).load().migrate()
            database = Database.connect(dataSource)
            repository = CopilotRemediationRepositoryImpl(database)
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            postgresContainer.stop()
        }
    }

    @BeforeEach
    fun cleanUp() {
        transaction(database) {
            CopilotRemediationsTable.deleteAll()
            CopilotAuthorizationRequestsTable.deleteAll()
        }
    }

    @Test
    fun `should allow only one claim when key is not yet started`() = runTest {
        assertTrue(repository.tryClaim(key, "a@nav.no", null, now.minusSeconds(300)))
        assertFalse(repository.tryClaim(key, "b@nav.no", null, now.minusSeconds(300)))
    }

    @Test
    fun `should replace started task only when its task id matches`() = runTest {
        repository.tryClaim(key, "a@nav.no", null, now.minusSeconds(300))
        repository.markStarted(key, "task-1", "https://github.com/tasks/1")

        assertFalse(repository.tryClaim(key, "b@nav.no", "task-other", now.minusSeconds(300)))
        assertTrue(repository.tryClaim(key, "b@nav.no", "task-1", now.minusSeconds(300)))
        assertFalse(repository.tryClaim(key, "c@nav.no", "task-1", now.minusSeconds(300)))
    }

    @Test
    fun `should restore previous task when replacing claim is released`() = runTest {
        repository.tryClaim(key, "a@nav.no", null, now.minusSeconds(300))
        repository.markStarted(key, "task-1", "https://github.com/tasks/1")
        repository.tryClaim(key, "b@nav.no", "task-1", now.minusSeconds(300))

        repository.releaseClaim(key)

        val remediation = repository.find(key)!!
        assertEquals(CopilotRemediationStatus.STARTED, remediation.status)
        assertEquals("task-1", remediation.taskId)
    }

    @Test
    fun `should delete row when first claim is released`() = runTest {
        repository.tryClaim(key, "a@nav.no", null, now.minusSeconds(300))

        repository.releaseClaim(key)

        assertNull(repository.find(key))
    }

    @Test
    fun `should consume authorization request only once`() = runTest {
        val request = CopilotAuthorizationRequest(
            state = "state-1",
            codeVerifier = "verifier",
            requestedBy = "a@nav.no",
            vulnerability = VulnerabilityRef(key.repository, key.vulnerabilityIdentifier, key.packageName),
            workloadId = null,
            returnPath = "/nb",
            expiresAt = Instant.parse("2099-01-01T00:00:00Z"),
        )
        repository.saveAuthorizationRequest(request)

        assertEquals(request, repository.consumeAuthorizationRequest("state-1"))
        assertNull(repository.consumeAuthorizationRequest("state-1"))
    }
}
