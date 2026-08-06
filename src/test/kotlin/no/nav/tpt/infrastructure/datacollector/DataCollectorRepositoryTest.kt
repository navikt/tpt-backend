package no.nav.tpt.infrastructure.datacollector

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import de.huxhorn.sulky.ulid.ULID
import java.time.Instant
import kotlin.test.Test
import kotlinx.coroutines.test.runTest
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.assertDoesNotThrow
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@Testcontainers
class DataCollectorRepositoryTest {
    private val ulid = ULID()

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

            Database.connect(dataSource)
            repository = DataCollectorRepositoryImpl()
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            postgresContainer.stop()
        }
    }

    @Test
    fun `store checks with no failures and read them back`() = runTest {
        val checkRecord = CheckRecord(ulid.nextValue(), "TheGoodCheck", "firstrepo", "ALL_GOOD",emptyList(), Instant.now())
        repository.insert(checkRecord)
        val checksForRepo = repository.allForRepo("firstrepo")
        assertEquals(1, checksForRepo.size)
    }

    @Test
    fun `store checks with failures and read them back`() = runTest {
        val checkRecord = CheckRecord(ulid.nextValue(), "TheFailingCheck", "secondrepo", "NEEDS_WORK",listOf("jau", "dill", "dall"), Instant.now())
        repository.insert(checkRecord)
        val checksForRepo = repository.allForRepo("secondrepo")
        assertEquals(1, checksForRepo.size)
        assertEquals(checkRecord, checksForRepo[0])
    }

    @Test
    fun `delete a check`() = runTest {
        val checkRecord = CheckRecord(ulid.nextValue(), "TheFailingCheck", "thirdrepo", "NEEDS_WORK",listOf("jau", "dill", "dall"), Instant.now())
        repository.insert(checkRecord)
        assertDoesNotThrow { repository.delete(checkRecord.id) }
        val checksForRepo = repository.allForRepo(checkRecord.repo)
        assertEquals(0, checksForRepo.size)
    }


}
