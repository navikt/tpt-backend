package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import org.slf4j.LoggerFactory
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

class NvdClient(
    private val httpClient: HttpClient,
    private val apiKey: String?,
    private val baseUrl: String = "https://services.nvd.nist.gov/rest/json/cves/2.0"
) {

    private val logger = LoggerFactory.getLogger(NvdClient::class.java)

    suspend fun getCvesByModifiedDate(
        lastModStartDate: LocalDateTime,
        lastModEndDate: LocalDateTime,
        startIndex: Int = 0,
        resultsPerPage: Int = 2000
    ): NvdResponse {
        return try {
            val response = httpClient.get(baseUrl) {
                parameter("lastModStartDate", formatDateForNvd(lastModStartDate))
                parameter("lastModEndDate", formatDateForNvd(lastModEndDate))
                parameter("startIndex", startIndex)
                parameter("resultsPerPage", resultsPerPage)
                apiKey?.let { header("apiKey", it) }
                contentType(ContentType.Application.Json)
            }

            if (!response.status.isSuccess()) {
                val errorBody = response.bodyAsText()
                logger.error(
                    "NVD API returned error status ${response.status.value}: $errorBody. " +
                    "URL: $baseUrl?lastModStartDate=${formatDateForNvd(lastModStartDate)}&" +
                    "lastModEndDate=${formatDateForNvd(lastModEndDate)}&startIndex=$startIndex&resultsPerPage=$resultsPerPage"
                )
                throw IllegalStateException("NVD API returned ${response.status.value}: $errorBody")
            }

            response.body()
        } catch (e: Exception) {
            logger.error("Failed to fetch CVEs from NVD API", e)
            throw e
        }
    }

    suspend fun getCvesByPublishedDate(
        pubStartDate: LocalDateTime,
        pubEndDate: LocalDateTime,
        startIndex: Int = 0,
        resultsPerPage: Int = 2000
    ): NvdResponse {
        return try {
            val response = httpClient.get(baseUrl) {
                parameter("pubStartDate", formatDateForNvd(pubStartDate))
                parameter("pubEndDate", formatDateForNvd(pubEndDate))
                parameter("startIndex", startIndex)
                parameter("resultsPerPage", resultsPerPage)
                apiKey?.let { header("apiKey", it) }
                contentType(ContentType.Application.Json)
            }

            if (!response.status.isSuccess()) {
                val errorBody = response.bodyAsText()
                logger.error(
                    "NVD API returned error status ${response.status.value}: $errorBody. " +
                    "URL: $baseUrl?pubStartDate=${formatDateForNvd(pubStartDate)}&" +
                    "pubEndDate=${formatDateForNvd(pubEndDate)}&startIndex=$startIndex&resultsPerPage=$resultsPerPage"
                )
                throw IllegalStateException("NVD API returned ${response.status.value}: $errorBody")
            }

            response.body()
        } catch (e: Exception) {
            logger.error("Failed to fetch CVEs from NVD API", e)
            throw e
        }
    }

    private fun formatDateForNvd(dateTime: LocalDateTime): String {
        // NVD API requires ISO 8601 format with UTC timezone (e.g., 2024-01-01T00:00:00.000Z)
        return dateTime.atZone(java.time.ZoneOffset.UTC)
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"))
    }

    suspend fun getCveByCveId(cveId: String): CveItem? {
        return try {
            val response = httpClient.get(baseUrl) {
                parameter("cveId", cveId)
                apiKey?.let { header("apiKey", it) }
                contentType(ContentType.Application.Json)
            }

            val nvdResponse: NvdResponse = response.body()

            if (nvdResponse.vulnerabilities.isEmpty()) {
                logger.warn("No CVE data found for $cveId in NVD")
                return null
            }

            nvdResponse.vulnerabilities.first().cve
        } catch (e: Exception) {
            logger.error("Failed to fetch CVE data from NVD for $cveId", e)
            null
        }
    }

    fun mapToNvdCveData(cve: CveItem): NvdCveData {
        val publishedDate = ZonedDateTime.parse(cve.published).toLocalDateTime()
        val lastModifiedDate = ZonedDateTime.parse(cve.lastModified).toLocalDateTime()
        val now = LocalDateTime.now()

        val daysOld = ChronoUnit.DAYS.between(publishedDate, now)
        val daysSinceModified = ChronoUnit.DAYS.between(lastModifiedDate, now)

        // Parse CISA KEV dates
        val cisaExploitAdd = cve.cisaExploitAdd?.let { LocalDate.parse(it) }
        val cisaActionDue = cve.cisaActionDue?.let { LocalDate.parse(it) }

        // Get Primary CVSS scores (prefer Primary over Secondary)
        val cvssV31 = cve.metrics?.cvssMetricV31?.firstOrNull { it.type == "Primary" }
            ?: cve.metrics?.cvssMetricV31?.firstOrNull()
        val cvssV30 = cve.metrics?.cvssMetricV30?.firstOrNull { it.type == "Primary" }
            ?: cve.metrics?.cvssMetricV30?.firstOrNull()
        val cvssV2 = cve.metrics?.cvssMetricV2?.firstOrNull { it.type == "Primary" }
            ?: cve.metrics?.cvssMetricV2?.firstOrNull()

        // Get English description
        val englishDescription = cve.descriptions
            ?.firstOrNull { it.lang == "en" }
            ?.value

        // Extract CWE IDs
        val cweIds = cve.weaknesses
            ?.filter { it.type == "Primary" || cve.weaknesses.size == 1 }
            ?.flatMap { it.description }
            ?.filter { it.lang == "en" }
            ?.map { it.value }
            ?: emptyList()

        // Extract references and check for exploits/patches
        val references = cve.references?.map { it.url } ?: emptyList()
        val hasExploitReference = cve.references
            ?.any { it.tags?.any { tag -> tag.equals("Exploit", ignoreCase = true) } == true }
            ?: false
        val hasPatchReference = cve.references
            ?.any { it.tags?.any { tag -> tag.equals("Patch", ignoreCase = true) } == true }
            ?: false

        return NvdCveData(
            cveId = cve.id,
            sourceIdentifier = cve.sourceIdentifier,
            vulnStatus = cve.vulnStatus,
            publishedDate = publishedDate,
            lastModifiedDate = lastModifiedDate,
            cisaExploitAdd = cisaExploitAdd,
            cisaActionDue = cisaActionDue,
            cisaRequiredAction = cve.cisaRequiredAction,
            cisaVulnerabilityName = cve.cisaVulnerabilityName,
            cvssV31Score = cvssV31?.cvssData?.baseScore,
            cvssV31Severity = cvssV31?.cvssData?.baseSeverity,
            cvssV30Score = cvssV30?.cvssData?.baseScore,
            cvssV30Severity = cvssV30?.cvssData?.baseSeverity,
            cvssV2Score = cvssV2?.cvssData?.baseScore,
            cvssV2Severity = when {
                cvssV2?.cvssData?.baseScore?.let { it >= 7.0 } == true -> "HIGH"
                cvssV2?.cvssData?.baseScore?.let { it >= 4.0 } == true -> "MEDIUM"
                else -> "LOW"
            },
            description = englishDescription,
            references = references,
            cweIds = cweIds,
            daysOld = daysOld,
            daysSinceModified = daysSinceModified,
            hasExploitReference = hasExploitReference,
            hasPatchReference = hasPatchReference
        )
    }
}

