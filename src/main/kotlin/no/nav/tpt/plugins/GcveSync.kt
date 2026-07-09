package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.kafka.GcveSyncCommand
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

fun Application.configureGcveSync() {
    val logger = LoggerFactory.getLogger("GcveSync")
    val kafkaProducer = dependencies.kafkaProducerService
    val leaderElection = dependencies.leaderElection
    val json = Json { ignoreUnknownKeys = true }

    leaderElection.startLeaderElectionChecks(this)

    launch {
        delay(60.seconds)

        while (true) {
            try {
                if (!leaderElection.isLeader()) {
                    logger.debug("Not leader, skipping GCVE sync publish")
                } else if (kafkaProducer == null) {
                    logger.warn("Kafka not configured, skipping scheduled GCVE sync")
                } else {
                    val command = GcveSyncCommand(
                        triggeredAt = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    )
                    kafkaProducer.publish("gcve_sync", json.encodeToString(GcveSyncCommand.serializer(), command))
                    logger.info("Published GCVE sync command to Kafka")
                }
            } catch (e: Exception) {
                logger.error("Failed to publish GCVE sync command", e)
            }

            delay(2.hours)
        }
    }

    logger.info("GCVE sync scheduler configured")
}
