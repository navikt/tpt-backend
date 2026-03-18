package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours

fun Application.configureVulnrichmentSync() {
    val logger = LoggerFactory.getLogger("VulnrichmentSync")
    val syncService = dependencies.vulnrichmentSyncService
    val leaderElection = dependencies.leaderElection

    leaderElection.startLeaderElectionChecks(this)

    launch {
        delay(1.hours)
        while (true) {
            try {
                if (leaderElection.isLeader()) {
                    logger.info("This pod is the leader - starting scheduled Vulnrichment stale refresh")
                    syncService.refreshStale()
                    logger.info("Scheduled Vulnrichment stale refresh completed")
                } else {
                    logger.debug("This pod is not the leader - skipping Vulnrichment stale refresh")
                }
            } catch (e: Exception) {
                logger.error("Vulnrichment stale refresh failed: ${e.message}", e)
            }
            delay(24.hours)
        }
    }
}
