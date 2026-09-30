package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

fun Application.configureGcveSync() {
    val logger = LoggerFactory.getLogger("GcveSync")
    val gcveSyncService = dependencies.gcveSyncService
    val leaderElection = dependencies.leaderElection

    leaderElection.startLeaderElectionChecks(this)

    launch {
        delay(60.seconds)

        while (true) {
            try {
                if (!leaderElection.isLeader()) {
                    logger.debug("Not leader, skipping scheduled GCVE sync")
                } else {
                    val count = gcveSyncService.performScheduledIncrementalSync()
                    logger.info("Scheduled GCVE sync complete, upserted $count CVEs")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.error("Scheduled GCVE sync failed", e)
            }

            delay(2.hours)
        }
    }

    logger.info("GCVE sync scheduler configured")
}
