package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob
import no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class GitHubRepositoryKafkaConsumer(
    kafkaConfig: KafkaConfig,
    private val repository: GitHubRepository,
    private val vulnerabilityTeamSyncService: VulnerabilityTeamSyncService? = null,
    private val vulnerabilityDataSyncJob: VulnerabilityDataSyncJob? = null,
    private val gcveSyncService: GcveSyncService? = null,
    private val gcveRepository: GcveRepository? = null,
    private val sseEventBus: SseEventBus? = null,
    groupId: String = "tpt-backend"
) : KafkaConsumerService(kafkaConfig, groupId) {

    private val logger = LoggerFactory.getLogger(GitHubRepositoryKafkaConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }
    private var messageCount = 0
    private var lastLogTime = System.currentTimeMillis()

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                "dockerfile_features" -> processDockerfileFeatures(record)
                "team_sync" -> processTeamSyncCommand(record)
                "vuln_data_sync" -> processVulnerabilityDataSyncCommand()
                "gcve_sync" -> processGcveSyncCommand()
                else -> processRepositoryMessage(record)
            }

            messageCount++
            val now = System.currentTimeMillis()
            if (now - lastLogTime >= 60000 && messageCount > 0) {
                logger.info("Processed $messageCount Kafka messages in the last minute")
                messageCount = 0
                lastLogTime = now
            }
        } catch (e: Exception) {
            logger.error("Error processing message with key ${record.key()}: ${record.value()}", e)
        }
    }

    private suspend fun processRepositoryMessage(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<GitHubRepositoryMessage>(record.value())
            try {
                repository.upsertRepositoryData(message)
            } catch (e: Exception) {
                logger.error("Error upserting GitHub repository data for ${message.getRepositoryIdentifier()}", e)
            }
        } catch (e: Exception) {
            logger.error("Error parsing GitHub repository message: ${record.value()}", e)
        }
    }

    private suspend fun processDockerfileFeatures(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<DockerfileFeaturesMessage>(record.value())
            try {
                repository.updateDockerfileFeatures(message.repoName, message.usesDistroless)
            } catch (e: Exception) {
                logger.error("Error updating dockerfile features for ${message.repoName}", e)
            }
        } catch (e: Exception) {
            logger.error("Error parsing dockerfile features message: ${record.value()}", e)
        }
    }

    private suspend fun processTeamSyncCommand(record: ConsumerRecord<String, String>) {
        val syncService = vulnerabilityTeamSyncService ?: run {
            logger.warn("Received team_sync command but VulnerabilityTeamSyncService is not configured")
            return
        }
        try {
            val command = json.decodeFromString<TeamSyncCommand>(record.value())
            val teamSlug = command.teamSlug
            logger.info("Processing team sync command for team $teamSlug")
            syncService.syncTeams(listOf(teamSlug))
            logger.info("Team sync complete for $teamSlug")
            sseEventBus?.emit(SseEvent.TeamSyncComplete(teamSlug, nowIso()))
        } catch (e: Exception) {
            logger.error("Error processing team_sync command: ${record.value()}", e)
        }
    }

    private suspend fun processVulnerabilityDataSyncCommand() {
        val syncJob = vulnerabilityDataSyncJob ?: run {
            logger.warn("Received vuln_data_sync command but VulnerabilityDataSyncJob is not configured")
            return
        }
        try {
            logger.info("Processing scheduled vulnerability data sync command")
            syncJob.syncAllTeams()
        } catch (e: Exception) {
            logger.error("Error processing vuln_data_sync command", e)
        }
    }

    private suspend fun processGcveSyncCommand() {
        val syncService = gcveSyncService ?: run {
            logger.warn("Received gcve_sync command but GcveSyncService is not configured")
            return
        }
        val repo = gcveRepository ?: run {
            logger.warn("Received gcve_sync command but GcveRepository is not configured")
            return
        }
        try {
            logger.info("Processing GCVE sync command")
            val lastSync = repo.getLastSyncTimestamp()
            val sinceInstant = lastSync ?: Instant.now().minusSeconds(86400)
            val since = sinceInstant.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            val trackedCveIds = repo.getTrackedCveIds()
            val count = syncService.performIncrementalSync(since = since, trackedCveIds = trackedCveIds)
            logger.info("GCVE sync command complete, upserted $count CVEs")
            sseEventBus?.emit(SseEvent.GcveSyncComplete(count, nowIso()))
        } catch (e: Exception) {
            logger.error("Error processing gcve_sync command", e)
        }
    }

    private fun nowIso(): String =
        Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
}
