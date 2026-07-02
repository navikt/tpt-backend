package no.nav.tpt.infrastructure.vulnrichment

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.nvd.InMemoryNvdRepository
import no.nav.tpt.infrastructure.nvd.NvdClient
import no.nav.tpt.infrastructure.nvd.NvdCveData
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.nvd.NvdTestDataBuilder
import no.nav.tpt.infrastructure.nvd.UpsertStats
import kotlin.test.Test
import kotlin.test.assertEquals

class SsvcBackfillServiceTest {

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    private val testBaseUrl = "https://test.nvd.api"

    private fun buildClient(handler: MockRequestHandler): NvdClient {
        val mockEngine = MockEngine(handler)
        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) { json(json) }
        }
        return NvdClient(httpClient, apiKey = null, baseUrl = testBaseUrl)
    }

    @Test
    fun `should return empty result when no cves are tracked in vulnrichment`() = runTest {
        val vulnrichmentRepository = MockVulnrichmentRepository()
        val nvdClient = buildClient { error("No NVD call expected") }
        val nvdRepository = InMemoryNvdRepository()

        val service = SsvcBackfillService(vulnrichmentRepository, nvdClient, nvdRepository)
        val result = service.run()

        assertEquals(0, result.totalCandidates)
        assertEquals(0, result.updatedWithSsvc)
        assertEquals(0, result.stillMissingInNvd)
        assertEquals(0, result.fetchFailures)
    }

    @Test
    fun `should count cves as updated when nvd returns ssvc data`() = runTest {
        val vulnrichmentRepository = MockVulnrichmentRepository()
        vulnrichmentRepository.upsertVulnrichmentData(
            listOf(
                VulnrichmentData("CVE-2024-0001", "active", "yes", "total"),
                VulnrichmentData("CVE-2024-0002", "poc", "no", "partial"),
            )
        )

        val nvdClient = buildClient { request ->
            val cveId = request.url.parameters["cveId"]
            val cve = NvdTestDataBuilder.buildCveItem(
                id = cveId!!,
                ssvcMetric = NvdTestDataBuilder.buildSsvcMetric(
                    exploitation = "Active",
                    automatable = "Yes",
                    technicalImpact = "Total"
                )
            )
            val response = NvdTestDataBuilder.buildNvdResponse(
                vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
            )
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdRepository = InMemoryNvdRepository()

        val service = SsvcBackfillService(vulnrichmentRepository, nvdClient, nvdRepository)
        val result = service.run()

        assertEquals(2, result.totalCandidates)
        assertEquals(2, result.updatedWithSsvc)
        assertEquals(0, result.stillMissingInNvd)
        assertEquals(0, result.fetchFailures)

        val stored = nvdRepository.getCveData("CVE-2024-0001")
        assertEquals("active", stored?.nvdSsvcExploitation)
    }

    @Test
    fun `should count cves as still missing when nvd has no cisa ssvc data yet`() = runTest {
        val vulnrichmentRepository = MockVulnrichmentRepository()
        vulnrichmentRepository.upsertVulnrichmentData(listOf(VulnrichmentData("CVE-2024-0003", "none", "no", "partial")))

        val nvdClient = buildClient { request ->
            val cveId = request.url.parameters["cveId"]!!
            val cve = NvdTestDataBuilder.buildCveItem(id = cveId)
            val response = NvdTestDataBuilder.buildNvdResponse(
                vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
            )
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdRepository = InMemoryNvdRepository()

        val service = SsvcBackfillService(vulnrichmentRepository, nvdClient, nvdRepository)
        val result = service.run()

        assertEquals(1, result.totalCandidates)
        assertEquals(0, result.updatedWithSsvc)
        assertEquals(1, result.stillMissingInNvd)
        assertEquals(0, result.fetchFailures)
    }

    @Test
    fun `should count fetch failures when nvd has no data for the cve`() = runTest {
        val vulnrichmentRepository = MockVulnrichmentRepository()
        vulnrichmentRepository.upsertVulnrichmentData(listOf(VulnrichmentData("CVE-2024-0004", "active", "yes", "total")))

        val nvdClient = buildClient {
            val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdRepository = InMemoryNvdRepository()

        val service = SsvcBackfillService(vulnrichmentRepository, nvdClient, nvdRepository)
        val result = service.run()

        assertEquals(1, result.totalCandidates)
        assertEquals(0, result.updatedWithSsvc)
        assertEquals(0, result.stillMissingInNvd)
        assertEquals(1, result.fetchFailures)
    }

    @Test
    fun `should continue processing remaining cves when upsert fails for one`() = runTest {
        val vulnrichmentRepository = MockVulnrichmentRepository()
        vulnrichmentRepository.upsertVulnrichmentData(
            listOf(
                VulnrichmentData("CVE-2024-FAIL", "active", "yes", "total"),
                VulnrichmentData("CVE-2024-OK", "active", "yes", "total"),
            )
        )

        val nvdClient = buildClient { request ->
            val cveId = request.url.parameters["cveId"]!!
            val cve = NvdTestDataBuilder.buildCveItem(
                id = cveId,
                ssvcMetric = NvdTestDataBuilder.buildSsvcMetric(exploitation = "Active", automatable = "Yes", technicalImpact = "Total")
            )
            val response = NvdTestDataBuilder.buildNvdResponse(
                vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
            )
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val delegate = InMemoryNvdRepository()
        val nvdRepository = object : NvdRepository {
            override suspend fun getCveData(cveId: String) = delegate.getCveData(cveId)
            override suspend fun getCveDataBatch(cveIds: List<String>) = delegate.getCveDataBatch(cveIds)
            override suspend fun upsertCve(cve: NvdCveData): UpsertStats {
                if (cve.cveId == "CVE-2024-FAIL") throw RuntimeException("DB error")
                return delegate.upsertCve(cve)
            }
            override suspend fun upsertCves(cves: List<NvdCveData>) = delegate.upsertCves(cves)
            override suspend fun getLastModifiedDate() = delegate.getLastModifiedDate()
            override suspend fun getCvesInKev() = delegate.getCvesInKev()
        }

        val service = SsvcBackfillService(vulnrichmentRepository, nvdClient, nvdRepository)
        val result = service.run()

        assertEquals(2, result.totalCandidates)
        assertEquals(1, result.updatedWithSsvc)
        assertEquals(0, result.stillMissingInNvd)
        assertEquals(1, result.fetchFailures)
    }
}
