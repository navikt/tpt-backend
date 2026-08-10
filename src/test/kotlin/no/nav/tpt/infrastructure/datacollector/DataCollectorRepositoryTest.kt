package no.nav.tpt.infrastructure.datacollector

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.time.Clock
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant
import kotlinx.coroutines.test.runTest
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@Testcontainers
class DataCollectorRepositoryTest {
    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("dcrepo_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var repository: DataCollectorRepositoryImpl

        @JvmStatic
        @BeforeAll
        fun setUp() {
            postgresContainer.start()

            val hikariConfig = HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            }
            val dataSource = HikariDataSource(hikariConfig)

            Flyway.configure()
                .dataSource(dataSource)
                .load()
                .migrate()

            val database = Database.connect(dataSource)
            repository = DataCollectorRepositoryImpl(database)
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            postgresContainer.stop()
        }
    }

    @Test
    fun `store checks with no failures and read them back`() = runTest {
        val checkResult = CheckResult.AllGood("TheGoodCheck", "firstrepo", Clock.System.now())
        repository.insert(checkResult)
        val checksForRepo = repository.allForRepo("firstrepo")
        assertEquals(1, checksForRepo.size)
    }

    @Test
    fun `store checks with failures and read them back`() = runTest {
        // Dirty trick to truncate the Kotlin Instant to milliseconds
        val now = Clock.System.now().toJavaInstant().truncatedTo(ChronoUnit.MILLIS).toKotlinInstant()
        val checkResult = CheckResult.NeedsWork("TheFailingCheck", "secondrepo", now, listOf("jau", "dill", "dall"))
        repository.insert(checkResult)
        val checksForRepo = repository.allForRepo("secondrepo")
        assertEquals(1, checksForRepo.size)
        assertEquals(checkResult, checksForRepo[0])
    }

    @Test
    fun `delete a check`() = runTest {
        val checkResult = CheckResult.NeedsWork("AnotherFailingCheck", "thirdrepo", Clock.System.now(), listOf("jau", "dill", "dall"))
        val id = repository.insert(checkResult)
        assertEquals(1, repository.delete(id))
        val checksForRepo = repository.allForRepo(checkResult.repo)
        assertEquals(0, checksForRepo.size)
    }


}
