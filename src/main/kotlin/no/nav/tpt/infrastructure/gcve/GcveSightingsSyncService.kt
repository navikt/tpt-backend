package no.nav.tpt.infrastructure.gcve

import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class GcveSightingsSyncService(
    private val gcveClient: GcveClient,
    private val sightingsRepository: GcveSightingsRepository,
) {
    private val logger = LoggerFactory.getLogger(GcveSightingsSyncService::class.java)

    suspend fun sync() {
        val lastFetchedDate = sightingsRepository.getLastSyncDate()
            ?: LocalDate.now(ZoneOffset.UTC).minusDays(30)

        logger.info("Starting sightings sync from $lastFetchedDate")

        val accumulator = SightingsAccumulator()

        val success = gcveClient.getSightingsSince(lastFetchedDate) { page ->
            accumulator.ingest(page)
        }

        if (!success) {
            logger.warn("Sightings sync aborted — could not fetch from GCVE API")
            return
        }

        val summaries = accumulator.toSummaries()
        sightingsRepository.upsertSightingsSummaries(summaries)
        sightingsRepository.updateLastSyncDate(LocalDate.now(ZoneOffset.UTC))

        logger.info("Sightings sync complete — upserted ${summaries.size} CVE summaries")
    }

    private fun parseTimestamp(raw: String): Instant? = try {
        if (raw.endsWith('Z') || raw.contains('+')) {
            Instant.from(DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(raw))
        } else {
            Instant.parse(raw + "Z")
        }
    } catch (e: Exception) {
        logger.debug("Could not parse sighting timestamp '$raw': ${e.message}")
        null
    }

    private inner class SightingsAccumulator {
        private data class Counts(
            var exploited: Int = 0,
            var poc: Int = 0,
            var seen: Int = 0,
            var latestExploited: Instant? = null,
            var latestPoc: Instant? = null,
            var latestSeen: Instant? = null,
        )

        private val byVuln = mutableMapOf<String, Counts>()

        fun ingest(sightings: List<GcveSighting>) {
            for (sighting in sightings) {
                val cveId = sighting.vulnerability.uppercase()
                if (!cveId.startsWith("CVE-")) continue

                val ts = parseTimestamp(sighting.creationTimestamp)
                val counts = byVuln.getOrPut(cveId) { Counts() }

                when (sighting.type.lowercase()) {
                    "exploited" -> {
                        counts.exploited++
                        if (ts != null && (counts.latestExploited == null || ts.isAfter(counts.latestExploited)))
                            counts.latestExploited = ts
                    }
                    "published-proof-of-concept" -> {
                        counts.poc++
                        if (ts != null && (counts.latestPoc == null || ts.isAfter(counts.latestPoc)))
                            counts.latestPoc = ts
                    }
                    "seen" -> {
                        counts.seen++
                        if (ts != null && (counts.latestSeen == null || ts.isAfter(counts.latestSeen)))
                            counts.latestSeen = ts
                    }
                    else -> {}
                }
            }
        }

        fun toSummaries(): List<GcveSightingsSummary> = byVuln.map { (cveId, counts) ->
            GcveSightingsSummary(
                cveId = cveId,
                exploitedCount = counts.exploited,
                pocCount = counts.poc,
                seenCount = counts.seen,
                latestExploitedAt = counts.latestExploited,
                latestPocAt = counts.latestPoc,
                latestSeenAt = counts.latestSeen,
            )
        }
    }
}
