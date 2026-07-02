package no.nav.tpt.infrastructure.gcve

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import no.nav.tpt.infrastructure.epss.InMemoryCircuitBreaker
import org.slf4j.LoggerFactory

class GcveClient(
    private val httpClient: HttpClient,
    private val baseUrl: String,
    private val apiKey: String? = null,
    private val circuitBreaker: InMemoryCircuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300),
) {

    private val logger = LoggerFactory.getLogger(GcveClient::class.java)

    private val maxRetries = 3
    private val defaultRetryAfterSeconds = 30L
    private val maxRetryAfterSeconds = 120L

    private val lenientJson = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    private val retryableStatuses = setOf(
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout,
    )

    suspend fun getVulnerability(cveId: String): GcveCveRecord? {
        if (circuitBreaker.isOpen()) {
            logger.warn("Circuit breaker is OPEN - skipping GCVE API call for $cveId")
            return null
        }

        return try {
            val response = executeWithRetry {
                httpClient.get("$baseUrl/vulnerability/$cveId") {
                    applyCommonHeaders()
                }
            } ?: return null

            when {
                response.status == HttpStatusCode.NotFound -> {
                    logger.debug("CVE $cveId not found in GCVE")
                    null
                }
                response.status.isSuccess() -> {
                    circuitBreaker.recordSuccess()
                    response.body<GcveCveRecord>()
                }
                else -> {
                    logger.warn("GCVE API returned ${response.status.value} for $cveId")
                    circuitBreaker.recordFailure()
                    null
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to fetch vulnerability $cveId from GCVE: ${e::class.simpleName}: ${e.message}", e)
            circuitBreaker.recordFailure()
            null
        }
    }

    /**
     * Fetches vulnerabilities updated since [since]. Restricted to [source] by default
     * (`cvelistv5` — the canonical CVE Record v5 format) because the unfiltered sweep
     * pulls from 70+ heterogeneous sources on this instance (CSAF vendor advisories,
     * OSV, FSTEC, CNVD, etc.) that do not conform to the CVE Record v5 shape our models
     * expect, and whose bulk payloads can be tens of megabytes per page.
     *
     * Returns `null` if the fetch itself failed (network error, non-success status,
     * circuit breaker open, exhausted retries) so callers can distinguish "could not
     * check for updates" from "checked, nothing new" and avoid advancing a sync
     * watermark past a window that was never actually observed.
     *
     * Individual records that still fail to parse (e.g. an unexpected shape slipping
     * through the source filter) are skipped and logged rather than failing the whole
     * page.
     */
    suspend fun getVulnerabilitiesSince(
        since: String,
        page: Int = 1,
        perPage: Int = 100,
        source: String? = "cvelistv5",
    ): List<GcveCveRecord>? {
        if (circuitBreaker.isOpen()) {
            logger.warn("Circuit breaker is OPEN - skipping GCVE incremental fetch")
            return null
        }

        return try {
            val response = executeWithRetry {
                httpClient.get("$baseUrl/vulnerability/") {
                    parameter("since", since)
                    parameter("per_page", perPage)
                    parameter("page", page)
                    parameter("date_sort", "updated")
                    source?.let { parameter("source", it) }
                    applyCommonHeaders()
                }
            } ?: return null

            if (response.status.isSuccess()) {
                circuitBreaker.recordSuccess()
                parseRecordsLeniently(response.bodyAsText())
            } else {
                logger.warn("GCVE incremental fetch returned ${response.status.value}")
                circuitBreaker.recordFailure()
                null
            }
        } catch (e: Exception) {
            logger.error(
                "Failed to fetch incremental vulnerabilities from GCVE: ${e::class.simpleName}: ${e.message}",
                e
            )
            circuitBreaker.recordFailure()
            null
        }
    }

    /**
     * Parses a JSON array of vulnerability records leniently: records that don't match
     * the expected CVE Record v5 shape are skipped and logged individually instead of
     * failing the entire batch.
     */
    private fun parseRecordsLeniently(bodyText: String): List<GcveCveRecord> {
        val elements = lenientJson.parseToJsonElement(bodyText).jsonArray

        val records = mutableListOf<GcveCveRecord>()
        var skipped = 0
        for (element in elements) {
            try {
                records.add(lenientJson.decodeFromJsonElement(GcveCveRecord.serializer(), element))
            } catch (e: Exception) {
                skipped++
                val cveIdHint = (element as? JsonObject)
                    ?.get("cveMetadata")?.jsonObject
                    ?.get("cveId")?.jsonPrimitive?.contentOrNull
                logger.warn(
                    "Skipping GCVE record with unexpected shape (cveId=${cveIdHint ?: "unknown"}): " +
                        "${e::class.simpleName}: ${e.message}"
                )
            }
        }

        if (skipped > 0) {
            logger.warn("Skipped $skipped/${elements.size} GCVE records with unexpected shape")
        }

        return records
    }

    suspend fun getEpssScore(cveId: String): GcveEpssData? {
        if (circuitBreaker.isOpen()) {
            logger.warn("Circuit breaker is OPEN - skipping GCVE EPSS fetch for $cveId")
            return null
        }

        return try {
            val response = executeWithRetry {
                httpClient.get("$baseUrl/epss/$cveId") {
                    applyCommonHeaders()
                }
            } ?: return null

            when {
                response.status == HttpStatusCode.NotFound -> null
                response.status.isSuccess() -> {
                    circuitBreaker.recordSuccess()
                    val epssResponse = response.body<GcveEpssResponse>()
                    epssResponse.data.firstOrNull()
                }
                else -> {
                    logger.warn("GCVE EPSS returned ${response.status.value} for $cveId")
                    circuitBreaker.recordFailure()
                    null
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to fetch EPSS score from GCVE for $cveId: ${e::class.simpleName}: ${e.message}", e)
            circuitBreaker.recordFailure()
            null
        }
    }

    private suspend fun executeWithRetry(request: suspend () -> HttpResponse): HttpResponse? {
        var attempt = 0
        while (true) {
            val response = request()

            if (response.status == HttpStatusCode.TooManyRequests) {
                attempt++
                if (attempt > maxRetries) {
                    logger.error("GCVE API rate limit exceeded after $maxRetries retries")
                    return null
                }
                val retryAfter = response.headers[HttpHeaders.RetryAfter]
                    ?.toLongOrNull()
                    ?.coerceIn(1, maxRetryAfterSeconds)
                    ?: defaultRetryAfterSeconds
                logger.warn("GCVE API rate limit hit (429), backing off ${retryAfter}s (attempt $attempt/$maxRetries)")
                delay(retryAfter * 1000)
                continue
            }

            if (response.status in retryableStatuses) {
                attempt++
                if (attempt > maxRetries) {
                    logger.error("GCVE API returned ${response.status.value} after $maxRetries retries")
                    return response
                }
                val backoff = (2L shl (attempt - 1)).coerceAtMost(30)
                logger.warn("GCVE API returned ${response.status.value}, retrying in ${backoff}s (attempt $attempt/$maxRetries)")
                delay(backoff * 1000)
                continue
            }

            return response
        }
    }

    private fun HttpRequestBuilder.applyCommonHeaders() {
        apiKey?.let { header("X-API-KEY", it) }
    }
}
