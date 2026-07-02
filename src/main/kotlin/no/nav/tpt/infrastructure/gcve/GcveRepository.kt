package no.nav.tpt.infrastructure.gcve

import java.time.Instant

data class GcveUpsertStats(val added: Int, val updated: Int)

interface GcveRepository {
    suspend fun getCveData(cveId: String): GcveCveData?
    suspend fun getCveDataBatch(cveIds: List<String>): Map<String, GcveCveData>
    suspend fun upsertCve(cveData: GcveCveData, rawResponse: String? = null): GcveUpsertStats
    suspend fun upsertCves(cves: List<GcveCveData>, rawResponses: Map<String, String> = emptyMap()): GcveUpsertStats
    suspend fun getLastSyncTimestamp(): Instant?
    suspend fun updateSyncTimestamp(timestamp: Instant)
    suspend fun getCveDataWithRaw(cveId: String): Pair<GcveCveData, String?>?
    suspend fun getTrackedCveIds(): Set<String>
    suspend fun getAllStoredCveIds(): Set<String>
}
