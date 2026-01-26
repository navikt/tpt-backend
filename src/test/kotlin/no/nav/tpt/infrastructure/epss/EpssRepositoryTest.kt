package no.nav.tpt.infrastructure.epss

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class EpssRepositoryTest {

    private lateinit var postgresContainer: PostgreSQLContainer<*>
    private lateinit var database: Database
    private lateinit var repository: EpssRepository

    @Before
    fun setup() {
        postgresContainer = PostgreSQLContainer(DockerImageName.parse("postgres:17"))
            .withDatabaseName("epss_test")
            .withUsername("test")
            .withPassword("test")
        postgresContainer.start()

        val hikariConfig = HikariConfig().apply {
            jdbcUrl = postgresContainer.jdbcUrl
            username = postgresContainer.username
            password = postgresContainer.password
            driverClassName = "org.postgresql.Driver"
        }
        val dataSource = HikariDataSource(hikariConfig)

        val flyway = Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()
        flyway.migrate()

        database = Database.connect(dataSource)
        repository = EpssRepositoryImpl(database)
    }

    @After
    fun teardown() {
        transaction(database) {
            EpssScores.deleteAll()
        }
        postgresContainer.stop()
    }

    @Test
    fun `should insert new EPSS score`() = runBlocking {
        val score = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.942510000",
            percentile = "0.999630000",
            date = "2026-01-20"
        )

        repository.upsertEpssScore(score)

        val result = repository.getEpssScore("CVE-2021-44228")
        assertNotNull(result)
        assertEquals("CVE-2021-44228", result.cve)
        assertEquals("0.942510000", result.epss)
        assertEquals("0.999630000", result.percentile)
        assertEquals("2026-01-20", result.date)
    }

    @Test
    fun `should update existing EPSS score`() = runBlocking {
        val initialScore = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.900000000",
            percentile = "0.950000000",
            date = "2026-01-19"
        )
        repository.upsertEpssScore(initialScore)

        Thread.sleep(100)

        val updatedScore = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.942510000",
            percentile = "0.999630000",
            date = "2026-01-20"
        )
        repository.upsertEpssScore(updatedScore)

        val result = repository.getEpssScore("CVE-2021-44228")
        assertNotNull(result)
        assertEquals("0.942510000", result.epss)
        assertEquals("0.999630000", result.percentile)
        assertEquals("2026-01-20", result.date)
    }

    @Test
    fun `should batch upsert multiple EPSS scores`() = runBlocking {
        val scores = listOf(
            EpssScore("CVE-2021-44228", "0.942510000", "0.999630000", "2026-01-20"),
            EpssScore("CVE-2022-22965", "0.943870000", "0.999930000", "2026-01-20"),
            EpssScore("CVE-2023-12345", "0.001230000", "0.456780000", "2026-01-20")
        )

        repository.upsertEpssScores(scores)

        val result = repository.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-12345"))
        assertEquals(3, result.size)
        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
        assertEquals("0.943870000", result["CVE-2022-22965"]?.epss)
        assertEquals("0.001230000", result["CVE-2023-12345"]?.epss)
    }

    @Test
    fun `should return empty map for non-existent CVEs`() = runBlocking {
        val result = repository.getEpssScores(listOf("CVE-9999-99999"))
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should identify stale CVEs based on threshold`() = runBlocking {
        val freshScore = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.942510000",
            percentile = "0.999630000",
            date = "2026-01-20"
        )
        repository.upsertEpssScore(freshScore)

        val staleCves = repository.getStaleCves(
            listOf("CVE-2021-44228", "CVE-9999-99999"),
            staleThresholdHours = 1
        )

        assertEquals(1, staleCves.size)
        assertTrue(staleCves.contains("CVE-9999-99999"))
    }

    @Test
    fun `should identify all missing CVEs as stale`() = runBlocking {
        val staleCves = repository.getStaleCves(
            listOf("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-12345"),
            staleThresholdHours = 24
        )

        assertEquals(3, staleCves.size)
        assertTrue(staleCves.containsAll(listOf("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-12345")))
    }

    @Test
    fun `should return empty list when no CVEs are stale`() = runBlocking {
        val score = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.942510000",
            percentile = "0.999630000",
            date = "2026-01-20"
        )
        repository.upsertEpssScore(score)

        val staleCves = repository.getStaleCves(
            listOf("CVE-2021-44228"),
            staleThresholdHours = 24
        )

        assertTrue(staleCves.isEmpty())
    }

    @Test
    fun `should handle batch upsert with mix of new and existing scores`() = runBlocking {
        val initialScore = EpssScore(
            cve = "CVE-2021-44228",
            epss = "0.900000000",
            percentile = "0.950000000",
            date = "2026-01-19"
        )
        repository.upsertEpssScore(initialScore)

        val scores = listOf(
            EpssScore("CVE-2021-44228", "0.942510000", "0.999630000", "2026-01-20"),
            EpssScore("CVE-2022-22965", "0.943870000", "0.999930000", "2026-01-20")
        )
        repository.upsertEpssScores(scores)

        val result = repository.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965"))
        assertEquals(2, result.size)
        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
        assertEquals("0.943870000", result["CVE-2022-22965"]?.epss)
    }

    @Test
    fun `should handle empty list in batch operations`() = runBlocking {
        repository.upsertEpssScores(emptyList())

        val result = repository.getEpssScores(emptyList())
        assertTrue(result.isEmpty())

        val staleCves = repository.getStaleCves(emptyList(), 24)
        assertTrue(staleCves.isEmpty())
    }

    @Test
    fun `should handle large batch upsert`() = runBlocking {
        val scores = (1..250).map { i ->
            EpssScore(
                cve = "CVE-2023-${i.toString().padStart(5, '0')}",
                epss = "0.${i.toString().padStart(9, '0')}",
                percentile = "0.${i.toString().padStart(9, '0')}",
                date = "2026-01-20"
            )
        }

        repository.upsertEpssScores(scores)

        val cveIds = scores.map { it.cve }
        val result = repository.getEpssScores(cveIds)
        assertEquals(250, result.size)
    }
}
