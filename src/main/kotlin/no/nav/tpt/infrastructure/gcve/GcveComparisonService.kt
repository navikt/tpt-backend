package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.Serializable
import no.nav.tpt.infrastructure.nvd.NvdRepository
import org.slf4j.LoggerFactory

class GcveComparisonService(
    private val gcveRepository: GcveRepository,
    private val nvdRepository: NvdRepository,
) {
    private val logger = LoggerFactory.getLogger(GcveComparisonService::class.java)

    suspend fun compareDataCoverage(): GcveComparisonReport {
        val trackedCveIds = gcveRepository.getTrackedCveIds()
            .filter { it.startsWith("CVE-", ignoreCase = true) }
            .toSet()

        val gcveStoredIds = gcveRepository.getAllStoredCveIds()

        val gcveCoveredIds = trackedCveIds.intersect(gcveStoredIds)
        val gcveMissingIds = trackedCveIds - gcveStoredIds

        val nvdBatch = nvdRepository.getCveDataBatch(gcveCoveredIds.toList())
        val gcveBatch = gcveRepository.getCveDataBatch(gcveCoveredIds.toList())

        val discrepancies = mutableListOf<CvssDiscrepancy>()

        for (cveId in gcveCoveredIds) {
            val nvdData = nvdBatch[cveId]
            val gcveData = gcveBatch[cveId]
            if (nvdData == null || gcveData == null) continue

            val nvdScore = nvdData.cvssV31Score
            val gcveScore = gcveData.cvssV31Score

            if (nvdScore != null && gcveScore != null && nvdScore != gcveScore) {
                discrepancies.add(
                    CvssDiscrepancy(
                        cveId = cveId,
                        nvdCvssV31Score = nvdScore,
                        gcveCvssV31Score = gcveScore,
                        nvdSeverity = nvdData.cvssV31Severity,
                        gcveSeverity = gcveData.cvssV31Severity,
                    )
                )
            }
        }

        val lastSync = gcveRepository.getLastSyncTimestamp()

        logger.info(
            "GCVE comparison: tracked=${trackedCveIds.size}, gcveCovered=${gcveCoveredIds.size}, " +
                "gcveMissing=${gcveMissingIds.size}, cvssDiscrepancies=${discrepancies.size}"
        )

        return GcveComparisonReport(
            totalTrackedCves = trackedCveIds.size,
            gcveCoveredCount = gcveCoveredIds.size,
            gcveMissingCount = gcveMissingIds.size,
            gcveMissingSample = gcveMissingIds.take(50).sorted(),
            cvssDiscrepancies = discrepancies.sortedByDescending {
                kotlin.math.abs(it.nvdCvssV31Score - it.gcveCvssV31Score)
            }.take(50),
            lastGcveSyncTimestamp = lastSync?.toString(),
        )
    }
}

@Serializable
data class GcveComparisonReport(
    val totalTrackedCves: Int,
    val gcveCoveredCount: Int,
    val gcveMissingCount: Int,
    val gcveMissingSample: List<String>,
    val cvssDiscrepancies: List<CvssDiscrepancy>,
    val lastGcveSyncTimestamp: String?,
)

@Serializable
data class CvssDiscrepancy(
    val cveId: String,
    val nvdCvssV31Score: Double,
    val gcveCvssV31Score: Double,
    val nvdSeverity: String?,
    val gcveSeverity: String?,
)
