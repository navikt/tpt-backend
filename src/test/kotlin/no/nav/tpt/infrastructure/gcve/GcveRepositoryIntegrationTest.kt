package no.nav.tpt.infrastructure.gcve

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.junit.jupiter.api.*
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Testcontainers
class GcveRepositoryIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("gcve_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database
        private lateinit var repository: GcveRepositoryImpl

        @JvmStatic
        @BeforeAll
        fun setUp() {
            val dataSource = HikariDataSource(HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            })
            Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate()
            database = Database.connect(dataSource)
            repository = GcveRepositoryImpl(database)
        }
    }

    @BeforeEach
    fun cleanDatabase() {
        transaction(database) {
            GcveCves.deleteAll()
            GcveSyncStatusTable.deleteAll()
        }
    }

    private fun buildTestCveData(
        cveId: String = "CVE-2021-44228",
        cnaSource: String? = "apache",
        publishedDate: LocalDateTime = LocalDateTime.of(2021, 12, 10, 0, 0),
        lastUpdatedDate: LocalDateTime = LocalDateTime.of(2025, 10, 21, 23, 25, 23),
        description: String? = "Log4j2 JNDI vulnerability",
        cvssV31Score: Double? = 10.0,
        cvssV31Severity: String? = "CRITICAL",
        cvssV31Vector: String? = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvssV40Score: Double? = null,
        cvssV40Severity: String? = null,
        cvssV40Vector: String? = null,
        cweIds: List<String> = listOf("CWE-502", "CWE-400"),
        references: List<String> = listOf("https://logging.apache.org/log4j/2.x/security.html"),
        hasExploitReference: Boolean = true,
        hasPatchReference: Boolean = true,
        ssvcExploitation: String? = "active",
        ssvcAutomatable: String? = "yes",
        ssvcTechnicalImpact: String? = "total",
        hasKevEntry: Boolean = true,
        kevDateAdded: String? = "2021-12-10",
        rawResponse: String? = null,
    ): GcveCveData = GcveCveData(
        cveId = cveId,
        cnaSource = cnaSource,
        publishedDate = publishedDate,
        lastUpdatedDate = lastUpdatedDate,
        description = description,
        cvssV31Score = cvssV31Score,
        cvssV31Severity = cvssV31Severity,
        cvssV31Vector = cvssV31Vector,
        cvssV40Score = cvssV40Score,
        cvssV40Severity = cvssV40Severity,
        cvssV40Vector = cvssV40Vector,
        cweIds = cweIds,
        references = references,
        hasExploitReference = hasExploitReference,
        hasPatchReference = hasPatchReference,
        ssvcExploitation = ssvcExploitation,
        ssvcAutomatable = ssvcAutomatable,
        ssvcTechnicalImpact = ssvcTechnicalImpact,
        hasKevEntry = hasKevEntry,
        kevDateAdded = kevDateAdded,
        daysOld = 0,
        daysSinceModified = 0,
    )

    @Test
    fun `should upsert and retrieve a single CVE`() = kotlinx.coroutines.test.runTest {
        val cveData = buildTestCveData()

        repository.upsertCve(cveData)

        val retrieved = repository.getCveData("CVE-2021-44228")
        assertNotNull(retrieved)
        assertEquals("CVE-2021-44228", retrieved.cveId)
        assertEquals("apache", retrieved.cnaSource)
        assertEquals(10.0, retrieved.cvssV31Score)
        assertEquals("CRITICAL", retrieved.cvssV31Severity)
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", retrieved.cvssV31Vector)
        assertEquals("Log4j2 JNDI vulnerability", retrieved.description)
        assertTrue(retrieved.cweIds.contains("CWE-502"))
        assertTrue(retrieved.cweIds.contains("CWE-400"))
        assertTrue(retrieved.hasExploitReference)
        assertTrue(retrieved.hasPatchReference)
        assertEquals("active", retrieved.ssvcExploitation)
        assertEquals("yes", retrieved.ssvcAutomatable)
        assertEquals("total", retrieved.ssvcTechnicalImpact)
        assertTrue(retrieved.hasKevEntry)
        assertEquals("2021-12-10", retrieved.kevDateAdded)
    }

    @Test
    fun `should return null for non-existent CVE`() = kotlinx.coroutines.test.runTest {
        val result = repository.getCveData("CVE-9999-99999")
        assertNull(result)
    }

    @Test
    fun `should update existing CVE on re-upsert`() = kotlinx.coroutines.test.runTest {
        val original = buildTestCveData(cvssV31Score = 9.8, cvssV31Severity = "CRITICAL")
        repository.upsertCve(original)

        val updated = buildTestCveData(cvssV31Score = 7.5, cvssV31Severity = "HIGH")
        repository.upsertCve(updated)

        val retrieved = repository.getCveData("CVE-2021-44228")
        assertNotNull(retrieved)
        assertEquals(7.5, retrieved.cvssV31Score)
        assertEquals("HIGH", retrieved.cvssV31Severity)
    }

    @Test
    fun `should batch upsert multiple CVEs`() = kotlinx.coroutines.test.runTest {
        val cves = listOf(
            buildTestCveData(cveId = "CVE-2021-44228"),
            buildTestCveData(cveId = "CVE-2024-3094", cnaSource = "redhat"),
            buildTestCveData(cveId = "CVE-2026-54431", cnaSource = "CERT-PL", cvssV31Score = null, cvssV40Score = 5.1, cvssV40Severity = "MEDIUM"),
        )

        val stats = repository.upsertCves(cves)
        assertEquals(3, stats.added)
        assertEquals(0, stats.updated)

        val batch = repository.getCveDataBatch(listOf("CVE-2021-44228", "CVE-2024-3094", "CVE-2026-54431"))
        assertEquals(3, batch.size)
        assertEquals("apache", batch["CVE-2021-44228"]?.cnaSource)
        assertEquals("redhat", batch["CVE-2024-3094"]?.cnaSource)
        assertEquals(5.1, batch["CVE-2026-54431"]?.cvssV40Score)
    }

    @Test
    fun `should return correct upsert stats for mixed insert and update`() = kotlinx.coroutines.test.runTest {
        repository.upsertCve(buildTestCveData(cveId = "CVE-2021-44228"))

        val stats = repository.upsertCves(
            listOf(
                buildTestCveData(cveId = "CVE-2021-44228"),
                buildTestCveData(cveId = "CVE-2024-3094"),
            )
        )

        assertEquals(1, stats.added)
        assertEquals(1, stats.updated)
    }

    @Test
    fun `should retrieve batch by CVE IDs`() = kotlinx.coroutines.test.runTest {
        repository.upsertCves(
            listOf(
                buildTestCveData(cveId = "CVE-2021-44228"),
                buildTestCveData(cveId = "CVE-2024-3094"),
                buildTestCveData(cveId = "CVE-2026-54431"),
            )
        )

        val batch = repository.getCveDataBatch(listOf("CVE-2021-44228", "CVE-2026-54431"))
        assertEquals(2, batch.size)
        assertTrue(batch.containsKey("CVE-2021-44228"))
        assertTrue(batch.containsKey("CVE-2026-54431"))
    }

    @Test
    fun `should return empty map for empty batch request`() = kotlinx.coroutines.test.runTest {
        val batch = repository.getCveDataBatch(emptyList())
        assertTrue(batch.isEmpty())
    }

    @Test
    fun `should persist and retrieve sync watermark`() = kotlinx.coroutines.test.runTest {
        assertNull(repository.getLastSyncTimestamp())

        val timestamp = Instant.parse("2026-07-02T12:00:00Z")
        repository.updateSyncTimestamp(timestamp)

        val retrieved = repository.getLastSyncTimestamp()
        assertNotNull(retrieved)
        assertEquals(timestamp, retrieved)
    }

    @Test
    fun `should update existing sync watermark`() = kotlinx.coroutines.test.runTest {
        val first = Instant.parse("2026-07-01T00:00:00Z")
        repository.updateSyncTimestamp(first)

        val second = Instant.parse("2026-07-02T12:00:00Z")
        repository.updateSyncTimestamp(second)

        val retrieved = repository.getLastSyncTimestamp()
        assertEquals(second, retrieved)
    }

    @Test
    fun `should handle CVE with CVSS v4 0 only`() = kotlinx.coroutines.test.runTest {
        val cveData = buildTestCveData(
            cveId = "CVE-2026-54431",
            cvssV31Score = null,
            cvssV31Severity = null,
            cvssV31Vector = null,
            cvssV40Score = 5.1,
            cvssV40Severity = "MEDIUM",
            cvssV40Vector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        )

        repository.upsertCve(cveData)

        val retrieved = repository.getCveData("CVE-2026-54431")
        assertNotNull(retrieved)
        assertNull(retrieved.cvssV31Score)
        assertEquals(5.1, retrieved.cvssV40Score)
        assertEquals("MEDIUM", retrieved.cvssV40Severity)
        assertTrue(retrieved.cvssV40Vector!!.startsWith("CVSS:4.0/"))
    }

    @Test
    fun `should store and retrieve raw response`() = kotlinx.coroutines.test.runTest {
        val rawJson = """{"cveMetadata":{"cveId":"CVE-2021-44228"}}"""
        val cveData = buildTestCveData(rawResponse = rawJson)

        repository.upsertCve(cveData, rawResponse = rawJson)

        val retrieved = repository.getCveDataWithRaw("CVE-2021-44228")
        assertNotNull(retrieved)
        assertEquals(rawJson, retrieved.second)
    }
}
