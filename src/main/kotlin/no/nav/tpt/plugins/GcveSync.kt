package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

fun Application.configureGcveSync() {
    val logger = LoggerFactory.getLogger("GcveSync")
    val gcveSyncService = dependencies.gcveSyncService
    val gcveRepository = dependencies.gcveRepository
    val leaderElection = dependencies.leaderElection

    leaderElection.startLeaderElectionChecks(this)

    launch {
        delay(60.seconds)

        while (true) {
            try {
                if (leaderElection.isLeader()) {
                    val lastSync = gcveRepository.getLastSyncTimestamp()
                    val since = lastSync
                        ?.atOffset(ZoneOffset.UTC)
                        ?.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                        ?: Instant.now().atOffset(ZoneOffset.UTC)
                            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)

                    val trackedCveIds = gcveRepository.getTrackedCveIds()
                    logger.info("Starting GCVE incremental sync since=$since, tracked CVEs: ${trackedCveIds.size}")

                    val count = gcveSyncService.performIncrementalSync(
                        since = since,
                        trackedCveIds = trackedCveIds,
                    )
                    logger.info("GCVE incremental sync completed, upserted $count CVEs")
                } else {
                    logger.debug("Not leader, skipping GCVE sync")
                }
            } catch (e: Exception) {
                logger.error("GCVE sync failed", e)
            }

            delay(2.hours)
        }
    }

    logger.info("GCVE sync scheduler configured")
}
