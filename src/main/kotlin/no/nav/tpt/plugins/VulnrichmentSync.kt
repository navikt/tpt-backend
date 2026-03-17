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
                syncService.refreshStale()
            } catch (e: Exception) {
                logger.error("Vulnrichment stale refresh failed: ${e.message}", e)
            }
            delay(24.hours)
        }
    }
}
