package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import java.time.LocalDateTime

/**
 * Mock NVD repository for testing
 */
class MockNvdRepository : NvdRepository {
    private val cves = mutableMapOf<String, NvdCveData>()

    init {
        populateWithSampleData()
    }

    private fun populateWithSampleData() {
        val now = LocalDateTime.now()
        val sampleCves = listOf(
            NvdCveData(
                cveId = "CVE-2023-12345",
                sourceIdentifier = "test@example.com",
                vulnStatus = "Analyzed",
                publishedDate = LocalDateTime.of(2023, 1, 15, 10, 0),
                lastModifiedDate = LocalDateTime.of(2023, 1, 20, 14, 30),
                cisaExploitAdd = java.time.LocalDate.of(2023, 1, 25),
                cisaActionDue = java.time.LocalDate.of(2023, 2, 15),
                cisaRequiredAction = "Apply mitigations per vendor instructions or discontinue use",
                cisaVulnerabilityName = "Remote Code Execution Vulnerability",
                cvssV31Score = 9.8,
                cvssV31Severity = "CRITICAL",
                cvssV30Score = null,
                cvssV30Severity = null,
                cvssV2Score = null,
                cvssV2Severity = null,
                description = "A critical vulnerability in test package allowing remote code execution",
                references = listOf("https://example.com/CVE-2023-12345"),
                cweIds = listOf("CWE-78", "CWE-94"),
                daysOld = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2023, 1, 15, 10, 0), now),
                daysSinceModified = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2023, 1, 20, 14, 30), now),
                hasExploitReference = true,
                hasPatchReference = true
            ),
            NvdCveData(
                cveId = "CVE-2023-54321",
                sourceIdentifier = "test@example.com",
                vulnStatus = "Analyzed",
                publishedDate = LocalDateTime.of(2023, 3, 10, 9, 0),
                lastModifiedDate = LocalDateTime.of(2023, 3, 15, 11, 0),
                cisaExploitAdd = null,
                cisaActionDue = null,
                cisaRequiredAction = null,
                cisaVulnerabilityName = null,
                cvssV31Score = 8.1,
                cvssV31Severity = "HIGH",
                cvssV30Score = null,
                cvssV30Severity = null,
                cvssV2Score = null,
                cvssV2Severity = null,
                description = "High severity authentication bypass vulnerability",
                references = listOf("https://example.com/CVE-2023-54321"),
                cweIds = listOf("CWE-287"),
                daysOld = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2023, 3, 10, 9, 0), now),
                daysSinceModified = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2023, 3, 15, 11, 0), now),
                hasExploitReference = false,
                hasPatchReference = true
            ),
            NvdCveData(
                cveId = "CVE-2024-11111",
                sourceIdentifier = "test@example.com",
                vulnStatus = "Analyzed",
                publishedDate = LocalDateTime.of(2024, 6, 1, 8, 0),
                lastModifiedDate = LocalDateTime.of(2024, 6, 5, 10, 0),
                cisaExploitAdd = null,
                cisaActionDue = null,
                cisaRequiredAction = null,
                cisaVulnerabilityName = null,
                cvssV31Score = 6.5,
                cvssV31Severity = "MEDIUM",
                cvssV30Score = null,
                cvssV30Severity = null,
                cvssV2Score = null,
                cvssV2Severity = null,
                description = "Medium severity SQL injection vulnerability",
                references = listOf("https://example.com/CVE-2024-11111"),
                cweIds = listOf("CWE-89"),
                daysOld = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2024, 6, 1, 8, 0), now),
                daysSinceModified = java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.of(2024, 6, 5, 10, 0), now),
                hasExploitReference = false,
                hasPatchReference = false
            )
        )
        sampleCves.forEach { cves[it.cveId] = it }
    }

    override suspend fun getCveData(cveId: String): NvdCveData? = cves[cveId]

    override suspend fun getCveDataBatch(cveIds: List<String>): Map<String, NvdCveData> =
        cves.filterKeys { it in cveIds }

    override suspend fun upsertCve(cve: NvdCveData): UpsertStats {
        val isUpdate = cves.containsKey(cve.cveId)
        cves[cve.cveId] = cve
        return if (isUpdate) UpsertStats(0, 1) else UpsertStats(1, 0)
    }

    override suspend fun upsertCves(cves: List<NvdCveData>): UpsertStats {
        var added = 0
        var updated = 0
        cves.forEach { cve ->
            val stats = upsertCve(cve)
            added += stats.added
            updated += stats.updated
        }
        return UpsertStats(added, updated)
    }

    override suspend fun getLastModifiedDate(): LocalDateTime? =
        cves.values.maxByOrNull { it.lastModifiedDate }?.lastModifiedDate

    override suspend fun getCvesInKev(): List<NvdCveData> =
        cves.values.filter { it.cisaExploitAdd != null }

    fun clear() = cves.clear()

    fun count(): Int = cves.size
}

/**
 * Creates a mock NVD client for testing - returns empty responses
 */
private fun createMockNvdClient(): NvdClient {
    val mockHttpClient = HttpClient(MockEngine) {
        engine {
            addHandler { _ ->
                respond(
                    content = """{"vulnerabilities":[],"totalResults":0,"resultsPerPage":0,"startIndex":0,"format":"NVD_CVE","version":"2.0","timestamp":"2024-01-01T00:00:00.000"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }
    }
        return NvdClient(mockHttpClient, apiKey = null, baseUrl = "http://localhost:8080/mock-nvd-api")
}

/**
 * Mock NVD sync service for testing - extends real NvdSyncService but uses mock implementations
 */
class MockNvdSyncService : NvdSyncService(
    nvdClient = createMockNvdClient(),
    repository = MockNvdRepository()
)

