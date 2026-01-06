package no.nav.tpt.infrastructure.nvd

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.test.runTest
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.jupiter.api.*
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.LocalDate
import java.time.LocalDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Testcontainers
class NvdRepositoryIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("nvd_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database
        private lateinit var repository: NvdRepositoryImpl

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

            // Run Flyway migrations (same as production)
            val flyway = Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
            flyway.migrate()

            database = Database.connect(dataSource)
            repository = NvdRepositoryImpl(database)
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
            NvdCves.deleteAll()
        }
    }

    @Test
    fun `should insert and retrieve CVE data`() = runTest {
        val cveData = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-TEST-1",
            description = "Test vulnerability"
        )

        repository.upsertCve(cveData)

        val retrieved = repository.getCveData("CVE-2024-TEST-1")

        assertNotNull(retrieved)
        assertEquals("CVE-2024-TEST-1", retrieved.cveId)
        assertEquals("Test vulnerability", retrieved.description)
    }

    @Test
    fun `should return null for non-existent CVE`() = runTest {
        val result = repository.getCveData("CVE-9999-NOTFOUND")

        assertNull(result)
    }

    @Test
    fun `should update existing CVE on upsert`() = runTest {
        val original = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-UPDATE",
            description = "Original description",
            cvssV31Score = 5.0
        )

        repository.upsertCve(original)

        val updated = original.copy(
            description = "Updated description",
            cvssV31Score = 7.5
        )

        repository.upsertCve(updated)

        val retrieved = repository.getCveData("CVE-2024-UPDATE")

        assertNotNull(retrieved)
        assertEquals("Updated description", retrieved.description)
        assertEquals(7.5, retrieved.cvssV31Score)
    }

    @Test
    fun `should batch upsert multiple CVEs`() = runTest {
        val cves = listOf(
            NvdTestDataBuilder.buildNvdCveData(cveId = "CVE-2024-BATCH-1"),
            NvdTestDataBuilder.buildNvdCveData(cveId = "CVE-2024-BATCH-2"),
            NvdTestDataBuilder.buildNvdCveData(cveId = "CVE-2024-BATCH-3")
        )

        repository.upsertCves(cves)

        val cve1 = repository.getCveData("CVE-2024-BATCH-1")
        val cve2 = repository.getCveData("CVE-2024-BATCH-2")
        val cve3 = repository.getCveData("CVE-2024-BATCH-3")

        assertNotNull(cve1)
        assertNotNull(cve2)
        assertNotNull(cve3)
    }

    @Test
    fun `should handle large batch upsert with chunking`() = runTest {
        val largeBatch = (1..1000).map { i ->
            NvdTestDataBuilder.buildNvdCveData(
                cveId = "CVE-2024-LARGE-$i",
                description = "Batch item $i"
            )
        }

        repository.upsertCves(largeBatch)

        val first = repository.getCveData("CVE-2024-LARGE-1")
        val middle = repository.getCveData("CVE-2024-LARGE-500")
        val last = repository.getCveData("CVE-2024-LARGE-1000")

        assertNotNull(first)
        assertNotNull(middle)
        assertNotNull(last)
    }

    @Test
    fun `should store and retrieve CISA KEV data`() = runTest {
        val kevCve = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-KEV",
            cisaExploitAdd = LocalDate.of(2024, 1, 15),
            cisaActionDue = LocalDate.of(2024, 2, 15),
            cisaRequiredAction = "Apply vendor patches immediately",
            cisaVulnerabilityName = "Critical Authentication Bypass"
        )

        repository.upsertCve(kevCve)

        val retrieved = repository.getCveData("CVE-2024-KEV")

        assertNotNull(retrieved)
        assertEquals(LocalDate.of(2024, 1, 15), retrieved.cisaExploitAdd)
        assertEquals(LocalDate.of(2024, 2, 15), retrieved.cisaActionDue)
        assertEquals("Apply vendor patches immediately", retrieved.cisaRequiredAction)
        assertEquals("Critical Authentication Bypass", retrieved.cisaVulnerabilityName)
    }

    @Test
    fun `should store and retrieve multiple CVSS versions`() = runTest {
        val multiCvssCve = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-MULTI-CVSS",
            cvssV31Score = 7.8,
            cvssV31Severity = "HIGH",
            cvssV30Score = 7.5,
            cvssV30Severity = "HIGH",
            cvssV2Score = 6.8,
            cvssV2Severity = "MEDIUM"
        )

        repository.upsertCve(multiCvssCve)

        val retrieved = repository.getCveData("CVE-2024-MULTI-CVSS")

        assertNotNull(retrieved)
        assertEquals(7.8, retrieved.cvssV31Score)
        assertEquals("HIGH", retrieved.cvssV31Severity)
        assertEquals(7.5, retrieved.cvssV30Score)
        assertEquals("HIGH", retrieved.cvssV30Severity)
        assertEquals(6.8, retrieved.cvssV2Score)
        assertEquals("MEDIUM", retrieved.cvssV2Severity)
    }

    @Test
    fun `should store and retrieve CWE IDs`() = runTest {
        val cveWithCwes = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-CWE",
            cweIds = listOf("CWE-79", "CWE-89", "CWE-120")
        )

        repository.upsertCve(cveWithCwes)

        val retrieved = repository.getCveData("CVE-2024-CWE")

        assertNotNull(retrieved)
        assertEquals(3, retrieved.cweIds.size)
        assertTrue(retrieved.cweIds.contains("CWE-79"))
        assertTrue(retrieved.cweIds.contains("CWE-89"))
        assertTrue(retrieved.cweIds.contains("CWE-120"))
    }

    @Test
    fun `should store and retrieve reference URLs`() = runTest {
        val cveWithRefs = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-REFS",
            references = listOf(
                "https://example.com/advisory1",
                "https://example.com/advisory2",
                "https://github.com/exploit"
            )
        )

        repository.upsertCve(cveWithRefs)

        val retrieved = repository.getCveData("CVE-2024-REFS")

        assertNotNull(retrieved)
        assertEquals(3, retrieved.references.size)
        assertTrue(retrieved.references.contains("https://example.com/advisory1"))
        assertTrue(retrieved.references.contains("https://github.com/exploit"))
    }

    @Test
    fun `should store and retrieve reference metadata flags`() = runTest {
        val cveWithExploit = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-EXPLOIT",
            hasExploitReference = true,
            hasPatchReference = false
        )

        repository.upsertCve(cveWithExploit)

        val retrieved = repository.getCveData("CVE-2024-EXPLOIT")

        assertNotNull(retrieved)
        assertTrue(retrieved.hasExploitReference)
        kotlin.test.assertFalse(retrieved.hasPatchReference)
    }

    @Test
    fun `should get last modified date`() = runTest {
        val old = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-OLD",
            lastModifiedDate = LocalDateTime.of(2024, 1, 1, 12, 0)
        )
        val recent = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-RECENT",
            lastModifiedDate = LocalDateTime.of(2024, 6, 15, 14, 30)
        )

        repository.upsertCves(listOf(old, recent))

        val lastModified = repository.getLastModifiedDate()

        assertNotNull(lastModified)
        assertEquals(LocalDateTime.of(2024, 6, 15, 14, 30), lastModified)
    }

    @Test
    fun `should return null for last modified date when database is empty`() = runTest {
        val lastModified = repository.getLastModifiedDate()

        assertNull(lastModified)
    }

    @Test
    fun `should get all CVEs in KEV catalog`() = runTest {
        val kevCve1 = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-KEV-1",
            cisaExploitAdd = LocalDate.of(2024, 1, 15)
        )
        val kevCve2 = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-KEV-2",
            cisaExploitAdd = LocalDate.of(2024, 2, 20)
        )
        val nonKevCve = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-NO-KEV",
            cisaExploitAdd = null
        )

        repository.upsertCves(listOf(kevCve1, kevCve2, nonKevCve))

        val kevCves = repository.getCvesInKev()

        assertEquals(2, kevCves.size)
        assertTrue(kevCves.any { it.cveId == "CVE-2024-KEV-1" })
        assertTrue(kevCves.any { it.cveId == "CVE-2024-KEV-2" })
        kotlin.test.assertFalse(kevCves.any { it.cveId == "CVE-2024-NO-KEV" })
    }

    @Test
    fun `should handle CVE with null optional fields`() = runTest {
        val minimalCve = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-MINIMAL",
            sourceIdentifier = null,
            vulnStatus = null,
            cisaExploitAdd = null,
            cisaActionDue = null,
            cisaRequiredAction = null,
            cisaVulnerabilityName = null,
            cvssV31Score = null,
            cvssV31Severity = null,
            cvssV30Score = null,
            cvssV30Severity = null,
            cvssV2Score = null,
            cvssV2Severity = null,
            description = null,
            references = emptyList(),
            cweIds = emptyList()
        )

        repository.upsertCve(minimalCve)

        val retrieved = repository.getCveData("CVE-2024-MINIMAL")

        assertNotNull(retrieved)
        assertEquals("CVE-2024-MINIMAL", retrieved.cveId)
        assertNull(retrieved.sourceIdentifier)
        assertNull(retrieved.cvssV31Score)
        assertEquals(0, retrieved.references.size)
        assertEquals(0, retrieved.cweIds.size)
    }

    @Test
    fun `should handle empty batch upsert gracefully`() = runTest {
        repository.upsertCves(emptyList())

        val lastModified = repository.getLastModifiedDate()
        assertNull(lastModified)
    }

    @Test
    fun `should correctly calculate days old and days since modified`() = runTest {
        val publishedDate = LocalDateTime.now().minusDays(30)
        val modifiedDate = LocalDateTime.now().minusDays(15)

        val cve = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-DAYS",
            publishedDate = publishedDate,
            lastModifiedDate = modifiedDate
        )

        repository.upsertCve(cve)

        val retrieved = repository.getCveData("CVE-2024-DAYS")

        assertNotNull(retrieved)
        assertTrue(retrieved.daysOld >= 29 && retrieved.daysOld <= 31)
        assertTrue(retrieved.daysSinceModified >= 14 && retrieved.daysSinceModified <= 16)
    }

    @Test
    fun `should preserve all fields during update`() = runTest {
        val complete = NvdTestDataBuilder.buildNvdCveData(
            cveId = "CVE-2024-COMPLETE",
            sourceIdentifier = "cve@mitre.org",
            vulnStatus = "Analyzed",
            cisaExploitAdd = LocalDate.of(2024, 1, 1),
            cisaActionDue = LocalDate.of(2024, 2, 1),
            cisaRequiredAction = "Patch immediately",
            cisaVulnerabilityName = "Test Vuln",
            cvssV31Score = 9.8,
            cvssV31Severity = "CRITICAL",
            description = "A serious vulnerability",
            references = listOf("https://example.com"),
            cweIds = listOf("CWE-79"),
            hasExploitReference = true,
            hasPatchReference = true
        )

        repository.upsertCve(complete)

        val updated = complete.copy(description = "Updated description")
        repository.upsertCve(updated)

        val retrieved = repository.getCveData("CVE-2024-COMPLETE")

        assertNotNull(retrieved)
        assertEquals("Updated description", retrieved.description)
        assertEquals("cve@mitre.org", retrieved.sourceIdentifier)
        assertEquals(LocalDate.of(2024, 1, 1), retrieved.cisaExploitAdd)
        assertEquals(9.8, retrieved.cvssV31Score)
        assertTrue(retrieved.hasExploitReference)
    }
}

