package no.nav.tpt.infrastructure.vulnrichment

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class VulnrichmentClient(
    private val httpClient: HttpClient,
    private val baseUrl: String = "https://cveawg.mitre.org/api",
) {
    private val logger = LoggerFactory.getLogger(VulnrichmentClient::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    private val consecutiveFailures = AtomicInteger(0)
    private val circuitOpenUntilMs = AtomicLong(0L)
    private val rateLimitedUntilMs = AtomicLong(0L)

    companion object {
        private const val CIRCUIT_OPEN_THRESHOLD = 5
        private const val CIRCUIT_OPEN_DURATION_MS = 60_000L
        private const val DEFAULT_RETRY_AFTER_S = 60L
        // ratelimit-remaining is in cost units (~837/request for a typical CVE record).
        // Pause when fewer than ~1 request worth of quota remains in the current window.
        private const val RATE_LIMIT_LOW_WATERMARK = 1000
    }

    suspend fun fetchCveData(cveId: String): VulnrichmentData? {
        val now = System.currentTimeMillis()
        if (now < circuitOpenUntilMs.get()) {
            logger.debug("Circuit open, skipping fetch for $cveId")
            return null
        }
        if (now < rateLimitedUntilMs.get()) {
            logger.debug("Rate limited, skipping fetch for $cveId")
            return null
        }

        return try {
            val response = httpClient.get("$baseUrl/cve/$cveId")
            handleRateLimitHeaders(response)
            when (response.status) {
                HttpStatusCode.OK -> {
                    consecutiveFailures.set(0)
                    val cveJson = json.decodeFromString<CveJson5>(response.bodyAsText())
                    extractSsvcDecisions(cveJson)
                }
                HttpStatusCode.NotFound -> null
                HttpStatusCode.TooManyRequests -> {
                    val retryAfter = response.headers[HttpHeaders.RetryAfter]?.toLongOrNull() ?: DEFAULT_RETRY_AFTER_S
                    rateLimitedUntilMs.set(System.currentTimeMillis() + retryAfter * 1000)
                    logger.warn("Rate limited (429) for $cveId, pausing ${retryAfter}s")
                    null
                }
                else -> {
                    recordFailure(response.status)
                    null
                }
            }
        } catch (e: Exception) {
            recordFailure(null)
            logger.warn("Failed to fetch Vulnrichment data for $cveId: ${e.message}")
            null
        }
    }

    private fun handleRateLimitHeaders(response: HttpResponse) {
        val remaining = response.headers["ratelimit-remaining"]?.toIntOrNull() ?: return
        val limit = response.headers["ratelimit-limit"]?.toIntOrNull()
        if (limit != null) {
            logger.debug("CVE API rate limit: $remaining/$limit remaining")
        }
        if (remaining <= RATE_LIMIT_LOW_WATERMARK) {
            val resetInSeconds = response.headers["ratelimit-reset"]?.toLongOrNull() ?: DEFAULT_RETRY_AFTER_S
            rateLimitedUntilMs.set(System.currentTimeMillis() + resetInSeconds * 1000)
            logger.warn("CVE API rate limit low ($remaining remaining), pausing for ${resetInSeconds}s")
        }
    }

    private fun recordFailure(status: HttpStatusCode?) {
        val count = consecutiveFailures.incrementAndGet()
        if (count >= CIRCUIT_OPEN_THRESHOLD) {
            circuitOpenUntilMs.set(System.currentTimeMillis() + CIRCUIT_OPEN_DURATION_MS)
            consecutiveFailures.set(0)
            logger.warn("Circuit breaker opened after $count failures (status=$status), pausing for ${CIRCUIT_OPEN_DURATION_MS / 1000}s")
        }
    }

    internal fun extractSsvcDecisions(cveJson: CveJson5): VulnrichmentData? {
        val cveId = cveJson.cveMetadata?.cveId ?: return null

        val cisaAdp = cveJson.containers?.adp?.firstOrNull {
            it.providerMetadata?.shortName?.equals("CISA-ADP", ignoreCase = true) == true
        } ?: return null

        val ssvcMetric = cisaAdp.metrics?.firstOrNull { metric ->
            metric.other?.type?.equals("ssvc", ignoreCase = true) == true
        } ?: return null

        val options = ssvcMetric.other?.content?.options ?: return null

        val exploitation = options.firstOrNull { it.containsKey("Exploitation") }?.get("Exploitation")
        val automatable = options.firstOrNull { it.containsKey("Automatable") }?.get("Automatable")
        val technicalImpact = options.firstOrNull { it.containsKey("Technical Impact") }?.get("Technical Impact")

        return VulnrichmentData(
            cveId = cveId,
            exploitationStatus = exploitation?.lowercase(),
            automatable = automatable?.lowercase(),
            technicalImpact = technicalImpact?.lowercase(),
        )
    }
}
