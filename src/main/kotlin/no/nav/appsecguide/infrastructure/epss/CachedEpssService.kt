package no.nav.appsecguide.infrastructure.epss

import no.nav.appsecguide.infrastructure.cache.Cache
import org.slf4j.LoggerFactory

class CachedEpssService(
    private val epssClient: EpssClient,
    private val cache: Cache<String, EpssScore>,
    private val circuitBreaker: CircuitBreaker
) : EpssService {
    private val logger = LoggerFactory.getLogger(CachedEpssService::class.java)

    companion object {
        // https://api.first.org/epss/
        private const val MAX_PARAMETER_LENGTH = 2000
        // https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
        private val CVE_PATTERN = Regex("^CVE-[0-9]{4}-[0-9]{4,19}$")
    }

    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
        if (cveIds.isEmpty()) {
            return emptyMap()
        }

        val validCveIds = cveIds.filter { it.matches(CVE_PATTERN) }
        val invalidCveIds = cveIds.filterNot { it.matches(CVE_PATTERN) }

        if (invalidCveIds.isNotEmpty()) {
            logger.warn("Filtered out ${invalidCveIds.size} invalid CVE ID(s): ${invalidCveIds.take(5).joinToString(", ")}${if (invalidCveIds.size > 5) "..." else ""}")
        }

        if (validCveIds.isEmpty()) {
            logger.debug("No valid CVE IDs to fetch EPSS scores for")
            return emptyMap()
        }

        val cachedScores = cache.getMany(validCveIds)
        val missingCveIds = validCveIds.filterNot { cachedScores.containsKey(it) }

        if (missingCveIds.isEmpty()) {
            logger.debug("Cache hit for all ${validCveIds.size} CVEs")
            return cachedScores
        }

        if (circuitBreaker.isOpen()) {
            logger.warn("Circuit breaker is OPEN - skipping EPSS API calls. Returning ${cachedScores.size} cached scores.")
            return cachedScores
        }

        logger.debug("Fetching ${missingCveIds.size} missing CVEs from EPSS API (${cachedScores.size} found in cache)")

        return try {
            val batches = createBatches(missingCveIds)
            logger.debug("Split ${missingCveIds.size} CVEs into ${batches.size} batch(es) to respect 2000 character limit")

            val fetchedScores = batches.flatMap { batch ->
                val response = epssClient.getEpssScores(batch)
                response.data
            }.associateBy { it.cve }

            circuitBreaker.recordSuccess()
            cache.putMany(fetchedScores)

            val allScores = cachedScores + fetchedScores

            logger.debug("Successfully fetched and cached ${fetchedScores.size} new EPSS scores")
            allScores
        } catch (_: EpssRateLimitException) {
            logger.error("Rate limit exceeded for EPSS API. Opening circuit breaker for 24 hours. Returning ${cachedScores.size} cached scores.")
            circuitBreaker.recordFailure()
            cachedScores
        } catch (e: EpssApiException) {
            logger.error("EPSS API error: ${e.message}. Returning ${cachedScores.size} cached scores.")
            cachedScores
        } catch (e: Exception) {
            logger.error("Unexpected error fetching EPSS scores: ${e.message}. Returning ${cachedScores.size} cached scores.", e)
            cachedScores
        }
    }

    private fun createBatches(cveIds: List<String>): List<List<String>> {
        val batches = mutableListOf<List<String>>()
        val currentBatch = mutableListOf<String>()
        var currentLength = 0

        for (cveId in cveIds) {
            val lengthWithComma = if (currentBatch.isEmpty()) cveId.length else cveId.length + 1

            if (currentLength + lengthWithComma > MAX_PARAMETER_LENGTH && currentBatch.isNotEmpty()) {
                batches.add(currentBatch.toList())
                currentBatch.clear()
                currentLength = 0
            }

            currentBatch.add(cveId)
            currentLength += lengthWithComma
        }

        if (currentBatch.isNotEmpty()) {
            batches.add(currentBatch.toList())
        }

        return batches
    }
}

