package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import java.time.Duration
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory

class TeamSyncConsumer(
    kafkaConfig: KafkaConfig,
    private val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService,
    private val kafkaProducer: SyncPublisher,
    pollTimeout: Duration = Duration.ofSeconds(1),
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-team-sync", autoCommit = false, pollTimeout = pollTimeout) {

    private val logger = LoggerFactory.getLogger(TeamSyncConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        if (record.key() != KafkaKey.TEAM_SYNC) {
            commitCurrentOffset()
            return
        }
        try {
            val command = json.decodeFromString<TeamSyncCommand>(record.value())
            val teamSlug = command.teamSlug

            logger.info("Starting team sync for $teamSlug")
            val results = vulnerabilityTeamSyncService.syncTeams(listOf(teamSlug))
            val result = results.first()

            if (!result.lockSkipped) {
                logger.info("Team sync complete for $teamSlug")
                kafkaProducer.publish(KafkaKey.TEAM_SYNC_COMPLETE, json.encodeToString(TeamSyncCompleteEvent(teamSlug)))
            } else {
                logger.info("Team sync skipped for $teamSlug — lock already held or data is fresh")
            }

            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing team_sync command: ${record.value()}", e)
        }
    }
}
