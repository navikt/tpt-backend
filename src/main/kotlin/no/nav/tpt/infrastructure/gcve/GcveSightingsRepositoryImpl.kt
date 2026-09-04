package no.nav.tpt.infrastructure.gcve

import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.LocalDate

class GcveSightingsRepositoryImpl(
    private val database: Database,
) : GcveSightingsRepository {
    private val logger = LoggerFactory.getLogger(GcveSightingsRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T = suspendTransaction(database) { block() }

    override suspend fun upsertSightingsSummaries(summaries: List<GcveSightingsSummary>) {
        if (summaries.isEmpty()) return
        dbQuery {
            summaries.chunked(500).forEach { batch ->
                batch.forEach { summary ->
                    GcveSightingsSummaryTable.upsert(GcveSightingsSummaryTable.cveId) {
                        it[cveId] = summary.cveId
                        it[exploitedCount] = summary.exploitedCount
                        it[pocCount] = summary.pocCount
                        it[seenCount] = summary.seenCount
                        it[latestExploitedAt] = summary.latestExploitedAt
                        it[latestPocAt] = summary.latestPocAt
                        it[latestSeenAt] = summary.latestSeenAt
                        it[updatedAt] = Instant.now()
                    }
                }
            }
        }
        logger.info("Upserted ${summaries.size} sightings summaries")
    }

    override suspend fun getSightingsSummaryBatch(cveIds: List<String>): Map<String, GcveSightingsSummary> =
        dbQuery {
            if (cveIds.isEmpty()) return@dbQuery emptyMap()
            GcveSightingsSummaryTable
                .selectAll()
                .where { GcveSightingsSummaryTable.cveId inList cveIds }
                .associate { row ->
                    row[GcveSightingsSummaryTable.cveId] to GcveSightingsSummary(
                        cveId = row[GcveSightingsSummaryTable.cveId],
                        exploitedCount = row[GcveSightingsSummaryTable.exploitedCount],
                        pocCount = row[GcveSightingsSummaryTable.pocCount],
                        seenCount = row[GcveSightingsSummaryTable.seenCount],
                        latestExploitedAt = row[GcveSightingsSummaryTable.latestExploitedAt],
                        latestPocAt = row[GcveSightingsSummaryTable.latestPocAt],
                        latestSeenAt = row[GcveSightingsSummaryTable.latestSeenAt],
                    )
                }
        }

    override suspend fun getLastSyncDate(): LocalDate? =
        dbQuery {
            GcveSightingsSyncStateTable
                .selectAll()
                .where { GcveSightingsSyncStateTable.id eq 1 }
                .firstOrNull()
                ?.get(GcveSightingsSyncStateTable.lastFetchedDate)
        }

    override suspend fun updateLastSyncDate(date: LocalDate) {
        dbQuery {
            GcveSightingsSyncStateTable.upsert(GcveSightingsSyncStateTable.id) {
                it[id] = 1
                it[lastFetchedDate] = date
                it[updatedAt] = Instant.now()
            }
        }
    }
}
