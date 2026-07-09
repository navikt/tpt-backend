package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class TeamSyncConsumer(
    kafkaConfig: KafkaConfig,
    private val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService,
    private val sseEventBus: SseEventBus,
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-team-sync", autoCommit = false) {

    private val logger = LoggerFactory.getLogger(TeamSyncConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        if (record.key() != "team_sync") {
            commitCurrentOffset()
            return
        }
        try {
            val command = json.decodeFromString<TeamSyncCommand>(record.value())
            val teamSlug = command.teamSlug
            logger.info("Starting team sync for $teamSlug")
            vulnerabilityTeamSyncService.syncTeams(listOf(teamSlug))
            logger.info("Team sync complete for $teamSlug")
            sseEventBus.emit(SseEvent.TeamSyncComplete(teamSlug, nowIso()))
            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing team_sync command: ${record.value()}", e)
        }
    }

    private fun nowIso(): String =
        Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
}
