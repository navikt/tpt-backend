package no.nav.tpt.infrastructure.epss

import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class EpssServiceImpl(
    private val epssClient: EpssClient,
    private val epssRepository: EpssRepository,
    private val circuitBreaker: InMemoryCircuitBreaker,
    private val staleThresholdHours: Int = 24
) : EpssService {
    private val logger = LoggerFactory.getLogger(EpssServiceImpl::class.java)

    // CVEs confirmed absent from the EPSS dataset, keyed by CVE ID to time of last check.
    // Avoids re-fetching on every request for CVEs that simply have no EPSS entry.
    private val notInEpssCache = ConcurrentHashMap<String, Instant>()

    companion object {
        private const val MAX_PARAMETER_LENGTH = 2000
        private val CVE_PATTERN = Regex("^CVE-[0-9]{4}-[0-9]{4,19}$")
    }

    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
        if (cveIds.isEmpty()) {
            return emptyMap()
        }

        val validCveIds = cveIds.filter { it.matches(CVE_PATTERN) }

        if (validCveIds.isEmpty()) {
            logger.debug("No valid CVE IDs to fetch EPSS scores for")
            return emptyMap()
        }

        val dbScores = epssRepository.getEpssScores(validCveIds)
        val staleCveIds = epssRepository.getStaleCves(validCveIds, staleThresholdHours)

        if (staleCveIds.isEmpty()) {
            logger.debug("All ${validCveIds.size} CVEs found in database and fresh")
            return dbScores
        }

        // Filter out CVEs recently confirmed as absent from EPSS (expires after staleThresholdHours)
        val staleThresholdSeconds = staleThresholdHours * 3600L
        val cacheExpiry = Instant.now().minusSeconds(staleThresholdSeconds)
        notInEpssCache.entries.removeIf { it.value < cacheExpiry }
        val cveIdsToFetch = staleCveIds.filter { !notInEpssCache.containsKey(it) }

        if (cveIdsToFetch.isEmpty()) {
            logger.debug("All ${staleCveIds.size} stale/missing CVEs are known not in EPSS dataset, skipping API call")
            return dbScores
        }

        if (circuitBreaker.isOpen()) {
            logger.warn("Circuit breaker is OPEN - skipping EPSS API calls. Returning ${dbScores.size} database scores (${cveIdsToFetch.size} are stale).")
            return dbScores
        }

        logger.info("Fetching ${cveIdsToFetch.size} stale/missing CVEs from EPSS API (${dbScores.size} found fresh in database)")

        return try {
            val batches = createBatches(cveIdsToFetch)
            logger.debug("Split ${cveIdsToFetch.size} CVEs into ${batches.size} batch(es) to respect 2000 character limit")

            val fetchedScores = batches.flatMap { batch ->
                val response = epssClient.getEpssScores(batch)
                response.data
            }.associateBy { it.cve }

            circuitBreaker.recordSuccess()
            epssRepository.upsertEpssScores(fetchedScores.values.toList())

            // Cache CVEs the API confirmed have no EPSS entry so we don't re-fetch every request
            val now = Instant.now()
            cveIdsToFetch.filter { it !in fetchedScores }.forEach { notInEpssCache[it] = now }
            if (cveIdsToFetch.size != fetchedScores.size) {
                logger.debug("${cveIdsToFetch.size - fetchedScores.size} CVEs have no EPSS entry — cached for ${staleThresholdHours}h")
            }

            val allScores = dbScores + fetchedScores

            logger.debug("Successfully fetched and stored ${fetchedScores.size} new/updated EPSS scores")
            allScores
        } catch (_: EpssRateLimitException) {
            logger.error("Rate limit exceeded for EPSS API. Opening circuit breaker. Returning ${dbScores.size} database scores.")
            circuitBreaker.recordFailure()
            dbScores
        } catch (e: EpssApiException) {
            logger.error("EPSS API error: ${e.message}. Returning ${dbScores.size} database scores.")
            dbScores
        } catch (e: Exception) {
            logger.error("Unexpected error fetching EPSS scores: ${e.message}. Returning ${dbScores.size} database scores.", e)
            dbScores
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
