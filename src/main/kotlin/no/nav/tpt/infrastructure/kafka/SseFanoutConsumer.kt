package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.Duration
import java.time.format.DateTimeFormatter
import java.util.UUID

class SseFanoutConsumer(
    kafkaConfig: KafkaConfig,
    private val sseEventBus: SseEventBus,
    pollTimeout: Duration = Duration.ofSeconds(1),
) : KafkaConsumerService(kafkaConfig, groupId = podScopedGroupId(), autoCommit = true, pollTimeout = pollTimeout) {

    private val logger = LoggerFactory.getLogger(SseFanoutConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                KafkaKey.TEAM_SYNC_STARTED -> {
                    val event = json.decodeFromString<TeamSyncStartedEvent>(record.value())
                    sseEventBus.emit(SseEvent.TeamSyncStarted(event.teamSlug, event.timestamp))
                }
                KafkaKey.TEAM_SYNC_COMPLETE -> {
                    val event = json.decodeFromString<TeamSyncCompleteEvent>(record.value())
                    sseEventBus.emit(SseEvent.TeamSyncComplete(event.teamSlug, nowIso()))
                }
                KafkaKey.GCVE_SYNC_COMPLETE -> {
                    val event = json.decodeFromString<GcveSyncCompleteEvent>(record.value())
                    sseEventBus.emit(SseEvent.GcveSyncComplete(event.cveCount, nowIso()))
                }
                KafkaKey.GITHUB_VULN_SYNC_STARTED -> {
                    val event = json.decodeFromString<GitHubVulnSyncStartedEvent>(record.value())
                    sseEventBus.emit(SseEvent.GitHubVulnSyncStarted(event.teams, event.timestamp))
                }
                KafkaKey.GITHUB_VULN_SYNC_COMPLETE -> {
                    val event = json.decodeFromString<GitHubVulnSyncCompleteEvent>(record.value())
                    sseEventBus.emit(SseEvent.GitHubVulnSyncComplete(event.teams, event.timestamp))
                }
            }
        } catch (e: Exception) {
            logger.error("Error processing SSE fanout record key=${record.key()}: ${record.value()}", e)
        }
    }

    private fun nowIso(): String =
        Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
}

private fun podScopedGroupId(): String = "tpt-backend-sse-sync-${UUID.randomUUID()}"
