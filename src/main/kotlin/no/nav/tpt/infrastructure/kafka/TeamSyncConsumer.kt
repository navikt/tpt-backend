package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory

class TeamSyncConsumer(
    kafkaConfig: KafkaConfig,
    private val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService,
    private val kafkaProducer: SyncPublisher,
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
            kafkaProducer.publish("team_sync_complete", json.encodeToString(TeamSyncCompleteEvent(teamSlug)))
            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing team_sync command: ${record.value()}", e)
        }
    }
}
