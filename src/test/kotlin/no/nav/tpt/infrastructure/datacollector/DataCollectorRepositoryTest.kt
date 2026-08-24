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
    // Dirty trick to truncate the Kotlin Instant to milliseconds
    val now = Clock.System.now().toJavaInstant().truncatedTo(ChronoUnit.MILLIS).toKotlinInstant()

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
    fun `store checks with good results and read them back`() = runTest {
        val checkResult = CheckResult.AllGood("TheGoodCheck", now)
        repository.insert(CheckResultsForRepo("firstRepo", listOf("firstTeam"),
            listOf(checkResult)))
        val fromDatabase = repository.allForOwner(listOf("firstTeam"))
        assertEquals(1, fromDatabase.size)
    }

    @Test
    fun `store checks with failures and read them back`() = runTest {
        val checkResult = CheckResult.NeedsWork("TheFailingCheck", now, listOf("jau", "dill", "dall"))
        val crr = CheckResultsForRepo("secondRepo", listOf("secondTeam"), listOf(checkResult))
        repository.insert(crr)
        val fromDatabase = repository.allForOwner(listOf("secondTeam"))
        assertEquals(1, fromDatabase.size)
        assertEquals(checkResult, fromDatabase[0])
    }

    @Test
    fun `all results for owner with multiple repos`() = runTest{
        val repoWithTeam4 = CheckResultsForRepo("thirdRepo", listOf("thirdTeam", "fourthTeam"), listOf(
            CheckResult.NeedsWork("AnotherFailingCheck", now, listOf("yolo", "whats", "up")),
            CheckResult.AllGood("AnotherGoodCheck", now)
        ))
        val repoWithoutTeam4 = CheckResultsForRepo("fourthRepo", listOf("thirdTeam"), listOf(
            CheckResult.NeedsWork("AnotherFailingCheck", now, listOf("jau", "dill", "dall")),
            CheckResult.AllGood("AnotherGoodCheck", Clock.System.now())
        ))
        repository.insert(repoWithTeam4)
        repository.insert(repoWithoutTeam4)

        val checksForTeam4FromDatabase = repository.allForOwner(listOf("fourthTeam"))
        assertEquals(repoWithTeam4.results, checksForTeam4FromDatabase)
    }

    @Test
    fun `existing checks with same name and repo should be replaced`() = runTest {
        val checkResult1 = CheckResult.NeedsWork("TheFailingCheck", now, listOf("jau", "dill", "dall"))
        val checkResult2 = CheckResult.NeedsWork("TheFailingCheck", now, listOf("jau", "dill", "replaced"))
        val crr1 = CheckResultsForRepo("fifthRepo", listOf("anotherTeam"), listOf(checkResult1))
        val crr2 = CheckResultsForRepo("fifthRepo", listOf("anotherTeam"), listOf(checkResult2))
        repository.insert(crr1)
        repository.insert(crr2)
        val fromDatabase = repository.allForOwner(listOf("anotherTeam"))
        assertEquals(1, fromDatabase.size)
        assertEquals(checkResult2, fromDatabase[0])
    }

}
