package no.nav.tpt.infrastructure.gcve

import java.time.Instant
import java.time.LocalDate

interface GcveSightingsRepository {
    suspend fun upsertSightingsSummaries(summaries: List<GcveSightingsSummary>)
    suspend fun getSightingsSummaryBatch(cveIds: List<String>): Map<String, GcveSightingsSummary>
    suspend fun getLastSyncDate(): LocalDate?
    suspend fun updateLastSyncDate(date: LocalDate)
}

data class GcveSightingsSummary(
    val cveId: String,
    val exploitedCount: Int,
    val pocCount: Int,
    val seenCount: Int,
    val latestExploitedAt: Instant?,
    val latestPocAt: Instant?,
    val latestSeenAt: Instant?,
)
