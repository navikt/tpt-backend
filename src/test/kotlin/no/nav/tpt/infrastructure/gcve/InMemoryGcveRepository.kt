package no.nav.tpt.infrastructure.gcve

import java.time.Instant

class InMemoryGcveRepository : GcveRepository {
    private val cves = mutableMapOf<String, GcveCveData>()
    private val rawResponses = mutableMapOf<String, String>()
    private var syncTimestamp: Instant? = null
    private var trackedCveIds: Set<String> = emptySet()

    override suspend fun getCveData(cveId: String): GcveCveData? = cves[cveId]

    override suspend fun getCveDataBatch(cveIds: List<String>): Map<String, GcveCveData> =
        cves.filterKeys { it in cveIds }

    override suspend fun upsertCve(cveData: GcveCveData, rawResponse: String?): GcveUpsertStats {
        val isUpdate = cves.containsKey(cveData.cveId)
        cves[cveData.cveId] = cveData
        rawResponse?.let { rawResponses[cveData.cveId] = it }
        return if (isUpdate) GcveUpsertStats(0, 1) else GcveUpsertStats(1, 0)
    }

    override suspend fun upsertCves(cves: List<GcveCveData>, rawResponses: Map<String, String>): GcveUpsertStats {
        var added = 0
        var updated = 0
        cves.forEach { cve ->
            val stats = upsertCve(cve, rawResponses[cve.cveId])
            added += stats.added
            updated += stats.updated
        }
        return GcveUpsertStats(added, updated)
    }

    override suspend fun getLastSyncTimestamp(): Instant? = syncTimestamp

    override suspend fun updateSyncTimestamp(timestamp: Instant) {
        syncTimestamp = timestamp
    }

    override suspend fun getCveDataWithRaw(cveId: String): Pair<GcveCveData, String?>? {
        val data = cves[cveId] ?: return null
        return Pair(data, rawResponses[cveId])
    }

    override suspend fun getTrackedCveIds(): Set<String> = trackedCveIds

    override suspend fun getAllStoredCveIds(): Set<String> = cves.keys.toSet()

    fun cveCount(): Int = cves.size
    fun setTrackedCveIds(ids: Set<String>) { trackedCveIds = ids }
    fun clear() {
        cves.clear()
        rawResponses.clear()
        syncTimestamp = null
    }
}
