package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import kotlinx.coroutines.delay
import org.slf4j.LoggerFactory
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

class NvdClient(
    private val httpClient: HttpClient,
    private val apiKey: String?,
    private val baseUrl: String,
    private val rateLimiter: NvdRateLimiter = NvdRateLimiter.forApiKey(apiKey),
) {

    private val logger = LoggerFactory.getLogger(NvdClient::class.java)

    private val maxRateLimitRetries = 3
    private val defaultRateLimitBackoffSeconds = 60L
    private val maxRateLimitBackoffSeconds = 300L

    /**
     * Executes an HTTP request against the NVD API, respecting [rateLimiter] before every
     * attempt and transparently retrying with backoff if NVD responds with 429 Too Many
     * Requests. Honors the `Retry-After` header when present. Gives up after
     * [maxRateLimitRetries] retries and returns the last (still-429) response, letting the
     * caller's existing error handling take over.
     */
    private suspend fun executeWithRateLimit(request: suspend () -> HttpResponse): HttpResponse {
        var attempt = 0
        while (true) {
            rateLimiter.acquire()
            val response = request()

            if (response.status != HttpStatusCode.TooManyRequests) {
                return response
            }

            attempt++
            if (attempt > maxRateLimitRetries) {
                logger.error("NVD API rate limit exceeded after $maxRateLimitRetries retries, giving up")
                return response
            }

            val retryAfterSeconds = response.headers[HttpHeaders.RetryAfter]
                ?.toLongOrNull()
                ?.coerceIn(1, maxRateLimitBackoffSeconds)
                ?: defaultRateLimitBackoffSeconds

            logger.warn(
                "NVD API rate limit hit (429), backing off for ${retryAfterSeconds}s " +
                    "(attempt $attempt/$maxRateLimitRetries)"
            )
            delay(retryAfterSeconds * 1000)
        }
    }

    suspend fun getCvesByModifiedDate(
        lastModStartDate: LocalDateTime,
        lastModEndDate: LocalDateTime,
        startIndex: Int = 0,
        resultsPerPage: Int = 2000
    ): NvdResponse {
        return try {
            val response = executeWithRateLimit {
                httpClient.get(baseUrl) {
                    parameter("lastModStartDate", formatDateForNvd(lastModStartDate))
                    parameter("lastModEndDate", formatDateForNvd(lastModEndDate))
                    parameter("startIndex", startIndex)
                    parameter("resultsPerPage", resultsPerPage)
                    apiKey?.let { header("apiKey", it) }
                    contentType(ContentType.Application.Json)
                }
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
            val response = executeWithRateLimit {
                httpClient.get(baseUrl) {
                    parameter("pubStartDate", formatDateForNvd(pubStartDate))
                    parameter("pubEndDate", formatDateForNvd(pubEndDate))
                    parameter("startIndex", startIndex)
                    parameter("resultsPerPage", resultsPerPage)
                    apiKey?.let { header("apiKey", it) }
                    contentType(ContentType.Application.Json)
                }
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

    private fun parseNvdTimestamp(timestamp: String): LocalDateTime {
        // NVD API sometimes returns timestamps with 'Z' suffix, sometimes without
        return if (timestamp.endsWith('Z')) {
            // Has timezone: 2024-01-01T00:00:00.000Z
            ZonedDateTime.parse(timestamp).toLocalDateTime()
        } else {
            // No timezone: 2002-01-02T05:00:00.000 - parse as LocalDateTime directly
            LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS"))
        }
    }

    suspend fun getCveByCveId(cveId: String): CveItem? {
        return try {
            val response = executeWithRateLimit {
                httpClient.get(baseUrl) {
                    parameter("cveId", cveId)
                    apiKey?.let { header("apiKey", it) }
                    contentType(ContentType.Application.Json)
                }
            }

            if (!response.status.isSuccess()) {
                logger.warn("NVD API returned error status ${response.status.value} for $cveId: ${response.bodyAsText()}")
                return null
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
        // Parse timestamps - NVD API sometimes returns with 'Z' suffix, sometimes without
        val publishedDate = parseNvdTimestamp(cve.published)
        val lastModifiedDate = parseNvdTimestamp(cve.lastModified)
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

        // Get English description (descriptions is required by schema)
        val englishDescription = cve.descriptions
            .firstOrNull { it.lang == "en" }
            ?.value

        // Extract CWE IDs
        val cweIds = cve.weaknesses
            ?.filter { it.type == "Primary" || cve.weaknesses.size == 1 }
            ?.flatMap { it.description }
            ?.filter { it.lang == "en" }
            ?.map { it.value }
            ?: emptyList()

        // Extract references and check for exploits/patches (references is required by schema)
        val references = cve.references.map { it.url }
        val hasExploitReference = cve.references
            .any { it.tags?.any { tag -> tag.equals("Exploit", ignoreCase = true) } == true }
        val hasPatchReference = cve.references
            .any { it.tags?.any { tag -> tag.equals("Patch", ignoreCase = true) } == true }

        // Extract SSVC fields from NVD-embedded CISA-ADP data
        val ssvc = cve.metrics?.extractNvdSsvc()

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
            hasPatchReference = hasPatchReference,
            nvdSsvcExploitation = ssvc?.exploitation,
            nvdSsvcAutomatable = ssvc?.automatable,
            nvdSsvcTechnicalImpact = ssvc?.technicalImpact,
        )
    }
}

