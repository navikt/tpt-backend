package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

fun Application.configureNvdSync() {
    val logger = LoggerFactory.getLogger("NvdSync")
    val nvdSyncService = dependencies.nvdSyncService
    val nvdRepository = dependencies.nvdRepository
    val leaderElection = dependencies.leaderElection

    // Start leader election checks
    leaderElection.startLeaderElectionChecks(this)

    // Track the initial sync job so incremental sync can wait for it
    var initialSyncJob: Job? = null

    // Check if we need initial sync
    launch {
        try {
            delay(30.seconds)
            val lastModified = nvdRepository.getLastModifiedDate()

            if (lastModified == null) {
                logger.info("No CVE data found in database. Initial sync is required.")
                logger.info("Initial sync will take approximately 1-2 hours and will run in the background.")
                logger.info("The application will start normally, but NVD data won't be available until sync completes.")
                logger.info("Incremental sync scheduler will wait for initial sync to complete before starting.")

                // Run initial sync in background with leader election
                // Keep retrying until a leader is elected and sync completes
                initialSyncJob = launch {
                    while (nvdRepository.getLastModifiedDate() == null) {
                        try {
                            val result = leaderElection.ifLeader {
                                logger.info("This pod is the leader - performing initial NVD sync")
                                nvdSyncService.performInitialSync()
                            }

                            if (result != null) {
                                logger.info("Initial NVD sync completed successfully!")
                            } else {
                                logger.info("This pod is not the leader - waiting 5 minutes before checking if data is available")
                                delay(5.minutes)
                            }
                        } catch (e: Exception) {
                            logger.error("Initial NVD sync failed, will retry in 1 hour", e)
                            delay(1.hours)
                        }
                    }
                    logger.info("NVD data is now available (lastModified: ${nvdRepository.getLastModifiedDate()})")
                }
            } else {
                logger.info("NVD data found. Last modified: $lastModified")
                logger.info("Incremental sync scheduler will start in 2 hours and then run every 2 hours")
            }
        } catch (e: Exception) {
            logger.error("Failed to check NVD sync status", e)
        }
    }

    // Schedule incremental sync every 2 hours with leader election
    launch {
        // If initial sync is running, wait for it to complete
        if (initialSyncJob != null) {
            logger.info("Waiting for initial sync to complete before starting incremental sync scheduler...")
            initialSyncJob.join()
            logger.info("Initial sync completed. Starting incremental sync scheduler.")
        } else {
            // Database has data - wait standard 2 hours to avoid deployment traffic
            logger.info("Incremental sync scheduler will start in 2 hours")
            delay(2.hours)
        }

        while (true) {
            try {
                val isLeader = leaderElection.isLeader()
                if (isLeader) {
                    logger.info("This pod is the leader - starting scheduled incremental NVD sync")
                    nvdSyncService.performIncrementalSync()
                    logger.info("Scheduled incremental NVD sync completed")
                } else {
                    logger.info("This pod is not the leader - skipping scheduled sync. Waiting 2 hours until next check.")
                }
            } catch (e: Exception) {
                logger.error("Scheduled incremental NVD sync failed", e)
            }

            // Wait 2 hours before next sync
            delay(2.hours)
        }
    }

    logger.info("NVD sync scheduler configured with Kubernetes leader election")
}

