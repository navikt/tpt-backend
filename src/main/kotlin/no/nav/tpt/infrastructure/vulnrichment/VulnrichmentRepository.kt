package no.nav.tpt.infrastructure.vulnrichment

import java.time.LocalDateTime

interface VulnrichmentRepository {
    suspend fun getVulnrichmentData(cveId: String): VulnrichmentData?
    suspend fun getVulnrichmentDataBatch(cveIds: List<String>): Map<String, VulnrichmentData>
    suspend fun upsertVulnrichmentData(data: List<VulnrichmentData>)
    suspend fun getStaleVulnrichmentIds(olderThan: LocalDateTime, limit: Int = 500): List<String>
}
