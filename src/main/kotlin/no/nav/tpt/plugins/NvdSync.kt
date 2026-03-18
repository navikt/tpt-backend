package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.CompletableDeferred
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

    leaderElection.startLeaderElectionChecks(this)

    // Signals whether an initial sync was needed and when it finishes.
    // null  = DB already had data, no initial sync needed
    // deferred = initial sync was launched; await it before starting incremental
    val initialSyncNeeded = CompletableDeferred<Boolean>()

    launch {
        try {
            delay(30.seconds)
            val lastModified = nvdRepository.getLastModifiedDate()

            if (lastModified == null) {
                logger.info("No CVE data found in database. Initial sync is required.")
                logger.info("Initial sync will take approximately 1-2 hours and will run in the background.")
                logger.info("The application will start normally, but NVD data won't be available until sync completes.")
                logger.info("Incremental sync scheduler will wait for initial sync to complete before starting.")

                initialSyncNeeded.complete(true)

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
            } else {
                logger.info("NVD data found. Last modified: $lastModified")
                initialSyncNeeded.complete(false)
            }
        } catch (e: Exception) {
            logger.error("Failed to check NVD sync status", e)
            initialSyncNeeded.complete(false)
        }
    }

    launch {
        val needed = initialSyncNeeded.await()
        if (needed) {
            logger.info("Waiting for initial sync to complete before starting incremental sync scheduler...")
            // Wait until DB has data — the loop above will have populated it
            while (nvdRepository.getLastModifiedDate() == null) {
                delay(1.minutes)
            }
            logger.info("Initial sync completed. Starting incremental sync scheduler.")
        } else {
            logger.info("Incremental NVD sync scheduler will start in 2 hours")
            delay(2.hours)
        }

        while (true) {
            try {
                if (leaderElection.isLeader()) {
                    logger.info("This pod is the leader - starting scheduled incremental NVD sync")
                    nvdSyncService.performIncrementalSync()
                    logger.info("Scheduled incremental NVD sync completed")
                } else {
                    logger.info("This pod is not the leader - skipping scheduled sync. Waiting 2 hours until next check.")
                }
            } catch (e: Exception) {
                logger.error("Scheduled incremental NVD sync failed", e)
            }

            delay(2.hours)
        }
    }

    logger.info("NVD sync scheduler configured with Kubernetes leader election")
}

