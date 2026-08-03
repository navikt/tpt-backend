package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.time.Instant

class GcveSyncService(
    private val gcveClient: GcveClient,
    private val gcveRepository: GcveRepository,
) {
    private val logger = LoggerFactory.getLogger(GcveSyncService::class.java)
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    suspend fun performIncrementalSync(
        since: String,
        trackedCveIds: Set<String>? = null,
        perPage: Int = 50,
    ): Int {
        logger.info("Starting GCVE incremental sync since=$since, tracked CVEs: ${trackedCveIds?.size ?: "all"}")

        var page = 1
        var totalUpserted = 0
        var fetchFailed = false

        while (true) {
            val records = gcveClient.getVulnerabilitiesSince(since, page = page, perPage = perPage)

            if (records == null) {
                logger.error(
                    "GCVE incremental sync failed fetching page $page — aborting this run. " +
                        "Sync watermark will NOT advance, next scheduled run will retry since=$since"
                )
                fetchFailed = true
                break
            }

            if (records.isEmpty()) break

            val filtered = if (trackedCveIds != null) {
                records.filter { it.cveMetadata.cveId in trackedCveIds }
            } else {
                records
            }

            if (filtered.isNotEmpty()) {
                val domainModels = filtered.map { GcveCveRecord.toDomainModel(it) }
                val rawResponses = filtered.associate { record ->
                    record.cveMetadata.cveId to json.encodeToString(GcveCveRecord.serializer(), record)
                }
                val stats = gcveRepository.upsertCves(domainModels, rawResponses)
                totalUpserted += stats.added + stats.updated
                logger.info("Page $page: fetched ${records.size}, filtered to ${filtered.size}, upserted (added: ${stats.added}, updated: ${stats.updated})")
            } else {
                logger.debug("Page $page: fetched ${records.size}, none in tracked set")
            }

            if (records.size < perPage) break
            page++
        }

        if (fetchFailed) {
            logger.warn("GCVE incremental sync completed WITH ERRORS. Upserted $totalUpserted CVEs before failure.")
        } else {
            gcveRepository.updateSyncTimestamp(Instant.now())
            logger.info("GCVE incremental sync complete. Total upserted: $totalUpserted")
        }

        return totalUpserted
    }
}
