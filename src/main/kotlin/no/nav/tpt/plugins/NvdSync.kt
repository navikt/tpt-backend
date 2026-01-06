package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours

fun Application.configureNvdSync() {
    val logger = LoggerFactory.getLogger("NvdSync")
    val nvdSyncService = dependencies.nvdSyncService
    val nvdRepository = dependencies.nvdRepository
    val leaderElection = dependencies.leaderElection

    // Start leader election checks
    leaderElection.startLeaderElectionChecks(this)

    // Check if we need initial sync
    launch {
        try {
            val lastModified = nvdRepository.getLastModifiedDate()

            if (lastModified == null) {
                logger.info("No CVE data found in database. Initial sync is required.")
                logger.info("Initial sync will take approximately 12-15 hours and will run in the background.")
                logger.info("The application will start normally, but NVD data won't be available until sync completes.")

                // Run initial sync in background with leader election
                launch {
                    try {
                        leaderElection.ifLeader {
                            logger.info("This pod is the leader - performing initial NVD sync")
                            nvdSyncService.performInitialSync()
                        }?.let {
                            logger.info("Initial NVD sync completed successfully!")
                        } ?: logger.info("This pod is not the leader - skipping initial sync")
                    } catch (e: Exception) {
                        logger.error("Initial NVD sync failed", e)
                    }
                }
            } else {
                logger.info("NVD data found. Last modified: $lastModified")
                logger.info("Incremental sync will run every 2 hours")
            }
        } catch (e: Exception) {
            logger.error("Failed to check NVD sync status", e)
        }
    }

    // Schedule incremental sync every 2 hours with leader election
    launch {
        // Wait a bit before starting incremental sync to allow initial sync to start if needed
        delay(5.hours)

        while (true) {
            try {
                leaderElection.ifLeader {
                    logger.info("This pod is the leader - starting scheduled incremental NVD sync")
                    nvdSyncService.performIncrementalSync()
                    logger.info("Scheduled incremental NVD sync completed")
                } ?: logger.debug("This pod is not the leader - skipping scheduled sync")
            } catch (e: Exception) {
                logger.error("Scheduled incremental NVD sync failed", e)
            }

            // Wait 2 hours before next sync
            delay(2.hours)
        }
    }

    logger.info("NVD sync scheduler configured with Kubernetes leader election")
}

