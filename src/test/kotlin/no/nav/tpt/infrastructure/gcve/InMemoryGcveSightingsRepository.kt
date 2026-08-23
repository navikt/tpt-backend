package no.nav.tpt.infrastructure.gcve

import java.time.LocalDate

class InMemoryGcveSightingsRepository : GcveSightingsRepository {
    private val summaries = mutableMapOf<String, GcveSightingsSummary>()
    private var lastSyncDate: LocalDate? = null

    override suspend fun upsertSightingsSummaries(newSummaries: List<GcveSightingsSummary>) {
        newSummaries.forEach { summaries[it.cveId] = it }
    }

    override suspend fun getSightingsSummaryBatch(cveIds: List<String>): Map<String, GcveSightingsSummary> =
        summaries.filterKeys { it in cveIds }

    override suspend fun getLastSyncDate(): LocalDate? = lastSyncDate

    override suspend fun updateLastSyncDate(date: LocalDate) {
        lastSyncDate = date
    }

    fun summaryCount(): Int = summaries.size
    fun getSummary(cveId: String): GcveSightingsSummary? = summaries[cveId]
    fun clear() {
        summaries.clear()
        lastSyncDate = null
    }
}
