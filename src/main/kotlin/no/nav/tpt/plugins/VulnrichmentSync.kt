package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

fun Application.configureVulnrichmentSync() {
    val logger = LoggerFactory.getLogger("VulnrichmentSync")
    val syncService = dependencies.vulnrichmentSyncService

    var initialSyncJob: Job? = null

    launch {
        try {
            delay(30.seconds)
            if (syncService.needsInitialSync()) {
                logger.info("No Vulnrichment data found. Performing initial sync.")
                initialSyncJob = launch {
                    while (syncService.needsInitialSync()) {
                        try {
                            syncService.performInitialSync()
                            if (!syncService.needsInitialSync()) {
                                logger.info("Vulnrichment initial sync completed.")
                            } else {
                                logger.info("Not the leader — waiting 5 minutes before retrying initial sync.")
                                delay(5.minutes)
                            }
                        } catch (e: Exception) {
                            logger.error("Vulnrichment initial sync failed, retrying in 1 hour: ${e.message}", e)
                            delay(1.hours)
                        }
                    }
                }
            } else {
                logger.info("Vulnrichment data present. Incremental sync will run every 24 hours.")
            }
        } catch (e: Exception) {
            logger.error("Failed to check Vulnrichment sync status: ${e.message}", e)
        }
    }

    launch {
        val jobToWait = initialSyncJob
        if (jobToWait != null) {
            logger.info("Waiting for Vulnrichment initial sync before starting incremental scheduler...")
            jobToWait.join()
        } else {
            delay(24.hours)
        }

        while (true) {
            try {
                syncService.sync()
            } catch (e: Exception) {
                logger.error("Vulnrichment incremental sync failed: ${e.message}", e)
            }
            delay(24.hours)
        }
    }
}
