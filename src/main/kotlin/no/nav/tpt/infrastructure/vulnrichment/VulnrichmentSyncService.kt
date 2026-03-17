package no.nav.tpt.infrastructure.vulnrichment

import no.nav.tpt.plugins.LeaderElection
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

class VulnrichmentSyncService(
    private val client: VulnrichmentClient,
    private val repository: VulnrichmentRepository,
    private val leaderElection: LeaderElection,
) {
    private val logger = LoggerFactory.getLogger(VulnrichmentSyncService::class.java)

    suspend fun sync() {
        leaderElection.ifLeader { performSync() }
    }

    private suspend fun performSync() {
        val since = repository.getLastUpdated()
            ?: LocalDateTime.now().minusDays(30)

        logger.info("Starting Vulnrichment sync since $since")

        val changed = try {
            client.fetchChangedCveData(since)
        } catch (e: Exception) {
            logger.error("Failed to fetch Vulnrichment data: ${e.message}")
            return
        }

        if (changed.isEmpty()) {
            logger.info("No Vulnrichment changes since $since")
            return
        }

        repository.upsertVulnrichmentData(changed)
        logger.info("Vulnrichment sync complete: ${changed.size} records updated")
    }
}
