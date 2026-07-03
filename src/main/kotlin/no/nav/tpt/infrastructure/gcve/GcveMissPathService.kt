package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory

class GcveMissPathService(
    private val gcveClient: GcveClient,
    private val gcveRepository: GcveRepository,
) {
    private val logger = LoggerFactory.getLogger(GcveMissPathService::class.java)
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    suspend fun fetchIfMissing(cveId: String): Boolean {
        val existing = gcveRepository.getCveData(cveId)
        if (existing != null) {
            logger.debug("CVE $cveId already in GCVE cache, skipping fetch")
            return false
        }

        val record = gcveClient.getVulnerability(cveId) ?: return false

        val domainModel = GcveCveRecord.toDomainModel(record)
        val rawResponse = json.encodeToString(GcveCveRecord.serializer(), record)
        gcveRepository.upsertCve(domainModel, rawResponse)
        logger.info("Fetched and stored GCVE data for $cveId via miss path")
        return true
    }

    suspend fun fetchMissing(cveIds: List<String>): Int {
        if (cveIds.isEmpty()) return 0

        val existing = gcveRepository.getCveDataBatch(cveIds)
        val missing = cveIds.filter { it !in existing }

        if (missing.isEmpty()) {
            logger.debug("All ${cveIds.size} CVEs already in GCVE cache")
            return 0
        }

        logger.info("Fetching ${missing.size} missing CVEs via GCVE miss path (${existing.size} already cached)")

        var fetched = 0
        var failed = 0
        missing.forEach { cveId ->
            try {
                val record = gcveClient.getVulnerability(cveId)
                if (record != null) {
                    val domainModel = GcveCveRecord.toDomainModel(record)
                    val rawResponse = json.encodeToString(GcveCveRecord.serializer(), record)
                    gcveRepository.upsertCve(domainModel, rawResponse)
                    fetched++
                } else {
                    logger.debug("GCVE API returned null for $cveId")
                    failed++
                }
            } catch (e: Exception) {
                logger.warn("Failed to fetch $cveId from GCVE: ${e.message}")
                failed++
            }
        }

        logger.info("Miss path complete: fetched $fetched, failed $failed, total ${missing.size}")
        return fetched
    }
}
