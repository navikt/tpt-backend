package no.nav.tpt.infrastructure.vulnrichment

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.test.runTest
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.junit.jupiter.api.*
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Testcontainers
class VulnrichmentRepositoryIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("vulnrichment_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database
        private lateinit var repository: VulnrichmentRepositoryImpl

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
                .locations("classpath:db/migration")
                .load()
                .migrate()

            database = Database.connect(dataSource)
            repository = VulnrichmentRepositoryImpl(database)
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            postgresContainer.stop()
        }
    }

    @BeforeEach
    fun cleanDatabase() {
        transaction(database) {
            VulnrichmentTable.deleteAll()
        }
    }

    @Test
    fun `should insert and retrieve vulnrichment data`() = runTest {
        val data = VulnrichmentData(
            cveId = "CVE-2024-1234",
            exploitationStatus = "active",
            automatable = "yes",
            technicalImpact = "total",
        )

        repository.upsertVulnrichmentData(listOf(data))

        val result = repository.getVulnrichmentData("CVE-2024-1234")

        assertNotNull(result)
        assertEquals("CVE-2024-1234", result.cveId)
        assertEquals("active", result.exploitationStatus)
        assertEquals("yes", result.automatable)
        assertEquals("total", result.technicalImpact)
    }

    @Test
    fun `should return null for non-existent CVE`() = runTest {
        val result = repository.getVulnrichmentData("CVE-9999-NOTFOUND")

        assertNull(result)
    }

    @Test
    fun `should update existing record on upsert`() = runTest {
        val original = VulnrichmentData(
            cveId = "CVE-2024-UPDATE",
            exploitationStatus = "none",
            automatable = "no",
            technicalImpact = "partial",
        )
        repository.upsertVulnrichmentData(listOf(original))

        val updated = original.copy(exploitationStatus = "active", automatable = "yes")
        repository.upsertVulnrichmentData(listOf(updated))

        val result = repository.getVulnrichmentData("CVE-2024-UPDATE")

        assertNotNull(result)
        assertEquals("active", result.exploitationStatus)
        assertEquals("yes", result.automatable)
        assertEquals("partial", result.technicalImpact)
    }

    @Test
    fun `should batch retrieve multiple CVEs`() = runTest {
        val data = listOf(
            VulnrichmentData("CVE-2024-BATCH-1", "active", "yes", "total"),
            VulnrichmentData("CVE-2024-BATCH-2", "poc", "no", "partial"),
            VulnrichmentData("CVE-2024-BATCH-3", "none", null, null),
        )
        repository.upsertVulnrichmentData(data)

        val result = repository.getVulnrichmentDataBatch(listOf("CVE-2024-BATCH-1", "CVE-2024-BATCH-2", "CVE-2024-BATCH-3"))

        assertEquals(3, result.size)
        assertEquals("active", result["CVE-2024-BATCH-1"]?.exploitationStatus)
        assertEquals("poc", result["CVE-2024-BATCH-2"]?.exploitationStatus)
        assertNull(result["CVE-2024-BATCH-3"]?.automatable)
    }

    @Test
    fun `should return empty map for batch query with no matches`() = runTest {
        val result = repository.getVulnrichmentDataBatch(listOf("CVE-9999-MISSING-1", "CVE-9999-MISSING-2"))

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return empty map for empty batch query`() = runTest {
        val result = repository.getVulnrichmentDataBatch(emptyList())

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should handle null optional fields`() = runTest {
        val data = VulnrichmentData(
            cveId = "CVE-2024-NULLS",
            exploitationStatus = null,
            automatable = null,
            technicalImpact = null,
        )
        repository.upsertVulnrichmentData(listOf(data))

        val result = repository.getVulnrichmentData("CVE-2024-NULLS")

        assertNotNull(result)
        assertNull(result.exploitationStatus)
        assertNull(result.automatable)
        assertNull(result.technicalImpact)
    }

    @Test
    fun `should get last updated timestamp after inserts`() = runTest {
        repository.upsertVulnrichmentData(listOf(
            VulnrichmentData("CVE-2024-TS-1", "active", "yes", "total"),
            VulnrichmentData("CVE-2024-TS-2", "none", "no", "partial"),
        ))

        val lastUpdated = repository.getLastUpdated()

        assertNotNull(lastUpdated)
    }

    @Test
    fun `should return null for last updated when database is empty`() = runTest {
        val lastUpdated = repository.getLastUpdated()

        assertNull(lastUpdated)
    }

    @Test
    fun `should handle large batch upsert with chunking`() = runTest {
        val largeBatch = (1..600).map { i ->
            VulnrichmentData("CVE-2024-LARGE-$i", "none", "no", "partial")
        }
        repository.upsertVulnrichmentData(largeBatch)

        assertNotNull(repository.getVulnrichmentData("CVE-2024-LARGE-1"))
        assertNotNull(repository.getVulnrichmentData("CVE-2024-LARGE-300"))
        assertNotNull(repository.getVulnrichmentData("CVE-2024-LARGE-600"))
    }

    @Test
    fun `should handle empty upsert gracefully`() = runTest {
        repository.upsertVulnrichmentData(emptyList())

        assertNull(repository.getLastUpdated())
    }

    @Test
    fun `should only return requested CVEs in batch query`() = runTest {
        repository.upsertVulnrichmentData(listOf(
            VulnrichmentData("CVE-2024-A", "active", "yes", "total"),
            VulnrichmentData("CVE-2024-B", "none", "no", "partial"),
        ))

        val result = repository.getVulnrichmentDataBatch(listOf("CVE-2024-A"))

        assertEquals(1, result.size)
        assertTrue(result.containsKey("CVE-2024-A"))
    }
}
