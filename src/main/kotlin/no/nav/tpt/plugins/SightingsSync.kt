package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

fun Application.configureSightingsSync() {
    val logger = LoggerFactory.getLogger("SightingsSync")
    val leaderElection = dependencies.leaderElection
    val sightingsSyncService = dependencies.gcveSightingsSyncService

    leaderElection.startLeaderElectionChecks(this)

    launch {
        delay(90.seconds)

        while (true) {
            try {
                if (!leaderElection.isLeader()) {
                    logger.debug("Not leader, skipping sightings sync")
                } else {
                    sightingsSyncService.sync()
                }
            } catch (e: Exception) {
                logger.error("Sightings sync failed", e)
            }

            delay(24.hours)
        }
    }

    logger.info("Sightings sync scheduler configured")
}
