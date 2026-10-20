package no.nav.tpt.infrastructure.securitystatus

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.test.runTest
import no.nav.tpt.domain.securitystatus.WorkloadSnapshot
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.BeforeAll
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

@Testcontainers
class WorkloadRepositoryIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("workload_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var repository: WorkloadRepositoryImpl

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
            Database.connect(dataSource)
            repository = WorkloadRepositoryImpl()
        }
    }

    private fun snapshot(id: String, deployedAt: Instant?) =
        WorkloadSnapshot(id, id, "app", "prod-gcp", deployedAt)

    @Test
    fun `should keep first seen, accumulate deployments and mark missing workloads removed`() = runTest {
        val team = "workload-team"
        val first = Instant.parse("2026-10-19T12:00:00Z")
        val second = first.plusSeconds(86400)
        val deploy1 = first.minusSeconds(1000)
        val deploy2 = second.minusSeconds(500)

        repository.syncTeamWorkloads(team, listOf(snapshot("a", deploy1), snapshot("b", null)), first)
        repository.syncTeamWorkloads(team, listOf(snapshot("a", deploy2)), second)
        repository.syncTeamWorkloads(team, listOf(snapshot("a", deploy2)), second)

        val facts = repository.getWorkloadFactsForTeams(listOf(team)).associateBy { it.appNaisId }
        assertEquals(first, facts.getValue("a").firstSeenAt)
        assertNull(facts.getValue("a").removedAt)
        assertEquals(listOf(deploy1, deploy2), facts.getValue("a").deployments.sorted())
        assertNotNull(facts.getValue("b").removedAt)
        assertEquals(emptyList(), facts.getValue("b").deployments)
    }
}
