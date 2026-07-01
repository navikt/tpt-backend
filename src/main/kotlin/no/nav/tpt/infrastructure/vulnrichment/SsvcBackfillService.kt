package no.nav.tpt.infrastructure.vulnrichment

import kotlinx.coroutines.delay
import no.nav.tpt.infrastructure.nvd.NvdClient
import no.nav.tpt.infrastructure.nvd.NvdRepository
import org.slf4j.LoggerFactory

data class SsvcBackfillResult(
    val totalCandidates: Int,
    val updatedWithSsvc: Int,
    val stillMissingInNvd: Int,
    val fetchFailures: Int,
)

/**
 * One-time backfill: re-fetches every CVE currently tracked in Vulnrichment from the NVD API
 * so that its embedded CISA-ADP SSVC data (exploitation, automatable, technical impact) is
 * persisted into `nvd_cves`. This is needed because NVD only embeds SSVC on a CVE record when
 * that record is fetched again — our regular incremental sync only re-pulls CVEs whose
 * lastModifiedDate falls within the sync window, which may not cover CVEs where CISA-ADP
 * added an SSVC decision without the CVE's NVD lastModifiedDate advancing.
 *
 * Intended to be run once (via an admin-triggered endpoint), and removed together with the
 * rest of the Vulnrichment integration once coverage is confirmed.
 */
class SsvcBackfillService(
    private val vulnrichmentRepository: VulnrichmentRepository,
    private val nvdClient: NvdClient,
    private val nvdRepository: NvdRepository,
    private val rateLimitDelayMs: Long = 6000,
) {
    private val logger = LoggerFactory.getLogger(SsvcBackfillService::class.java)

    suspend fun run(): SsvcBackfillResult {
        val cveIds = vulnrichmentRepository.getAllVulnrichmentCveIds()
        logger.info("Starting SSVC backfill for ${cveIds.size} CVEs tracked in Vulnrichment")

        var updatedWithSsvc = 0
        var stillMissingInNvd = 0
        var fetchFailures = 0

        cveIds.forEachIndexed { index, cveId ->
            try {
                val cveItem = nvdClient.getCveByCveId(cveId)
                if (cveItem == null) {
                    fetchFailures++
                    logger.warn("SSVC backfill: no data returned from NVD for $cveId")
                } else {
                    val cveData = nvdClient.mapToNvdCveData(cveItem)
                    nvdRepository.upsertCve(cveData)
                    if (cveData.nvdSsvcExploitation != null) {
                        updatedWithSsvc++
                    } else {
                        stillMissingInNvd++
                        logger.info("SSVC backfill: $cveId has no CISA-ADP SSVC data in NVD yet")
                    }
                }
            } catch (e: Exception) {
                fetchFailures++
                logger.error("SSVC backfill: failed to process $cveId: ${e.message}", e)
            }

            if (index < cveIds.lastIndex) {
                delay(rateLimitDelayMs)
            }
        }

        val result = SsvcBackfillResult(
            totalCandidates = cveIds.size,
            updatedWithSsvc = updatedWithSsvc,
            stillMissingInNvd = stillMissingInNvd,
            fetchFailures = fetchFailures,
        )

        logger.info(
            "SSVC backfill completed: total=${result.totalCandidates}, " +
                "updatedWithSsvc=${result.updatedWithSsvc}, " +
                "stillMissingInNvd=${result.stillMissingInNvd}, " +
                "fetchFailures=${result.fetchFailures}"
        )

        return result
    }
}
