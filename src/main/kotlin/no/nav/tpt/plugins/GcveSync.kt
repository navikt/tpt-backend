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
                    val sinceInstant = lastSync ?: Instant.now().minusSeconds(86400)
                    val since = sinceInstant
                        .atOffset(ZoneOffset.UTC)
                        .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)

                    if (lastSync == null) {
                        logger.info("No GCVE sync watermark found, starting with 24h lookback: since=$since")
                    }

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
