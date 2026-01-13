package no.nav.tpt.infrastructure.epss

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import org.slf4j.LoggerFactory

class EpssClient(
    private val httpClient: HttpClient,
    private val baseUrl: String
) {
    private val logger = LoggerFactory.getLogger(EpssClient::class.java)

    suspend fun getEpssScores(cveIds: List<String>): EpssResponse {
        if (cveIds.isEmpty()) {
            return EpssResponse(status = "OK", total = 0, data = emptyList())
        }

        val cveParam = cveIds.joinToString(",")
        logger.debug("Fetching EPSS scores for ${cveIds.size} CVEs")

        val response: HttpResponse = httpClient.get("$baseUrl/epss") {
            parameter("cve", cveParam)
        }

        return when (response.status) {
            HttpStatusCode.OK -> response.body()
            HttpStatusCode.TooManyRequests -> {
                logger.error("EPSS API rate limit exceeded (429 Too Many Requests). Limit resets daily.")
                throw EpssRateLimitException("Rate limit exceeded")
            }
            else -> {
                logger.error("EPSS API returned error status: ${response.status.value} ${response.status.description}")
                throw EpssApiException("EPSS API error: ${response.status.value}")
            }
        }
    }
}

class EpssRateLimitException(message: String) : Exception(message)
class EpssApiException(message: String) : Exception(message)

