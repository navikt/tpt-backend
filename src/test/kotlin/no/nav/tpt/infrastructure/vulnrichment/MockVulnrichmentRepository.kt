package no.nav.tpt.infrastructure.vulnrichment

import java.time.LocalDateTime

class MockVulnrichmentRepository : VulnrichmentRepository {
    private val data = mutableMapOf<String, VulnrichmentData>()

    override suspend fun getVulnrichmentData(cveId: String): VulnrichmentData? = data[cveId]

    override suspend fun getVulnrichmentDataBatch(cveIds: List<String>): Map<String, VulnrichmentData> =
        cveIds.mapNotNull { id -> data[id]?.let { id to it } }.toMap()

    override suspend fun upsertVulnrichmentData(data: List<VulnrichmentData>) {
        data.forEach { this.data[it.cveId] = it }
    }

    override suspend fun getStaleVulnrichmentIds(olderThan: LocalDateTime, limit: Int): List<String> = emptyList()
}
