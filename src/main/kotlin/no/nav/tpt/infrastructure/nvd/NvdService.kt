package no.nav.tpt.infrastructure.nvd

import java.time.LocalDateTime

data class UpsertStats(val added: Int, val updated: Int)

interface NvdRepository {
    suspend fun getCveData(cveId: String): NvdCveData?
    suspend fun getCveDataBatch(cveIds: List<String>): Map<String, NvdCveData>
    suspend fun upsertCve(cve: NvdCveData): UpsertStats
    suspend fun upsertCves(cves: List<NvdCveData>): UpsertStats
    suspend fun getLastModifiedDate(): LocalDateTime?
    suspend fun getCvesInKev(): List<NvdCveData>
}

