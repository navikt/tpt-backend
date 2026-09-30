package no.nav.tpt.infrastructure.gcve

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventPublisher
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class GcveSyncService(
    private val gcveClient: GcveClient,
    private val gcveRepository: GcveRepository,
    private val sseEventPublisher: SseEventPublisher? = null,
) {
    private val logger = LoggerFactory.getLogger(GcveSyncService::class.java)
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    suspend fun performScheduledIncrementalSync(): Int {
        val sinceInstant = gcveRepository.getLastSyncTimestamp() ?: Instant.now().minusSeconds(86400)
        val since = sinceInstant.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        val trackedCveIds = gcveRepository.getTrackedCveIds()
        logger.info("Starting GCVE incremental sync since=$since, tracked CVEs: ${trackedCveIds.size}")
        return performIncrementalSync(since = since, trackedCveIds = trackedCveIds)
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

        val timestamp = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        try {
            sseEventPublisher?.publish(SseEvent.GcveSyncComplete(totalUpserted, timestamp))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.warn("Failed to publish gcve_sync_complete SSE event", e)
        }

        return totalUpserted
    }
}
