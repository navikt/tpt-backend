package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID

class SseFanoutConsumer(
    kafkaConfig: KafkaConfig,
    private val sseEventBus: SseEventBus,
) : KafkaConsumerService(kafkaConfig, groupId = podScopedGroupId(), autoCommit = true, offsetReset = "latest") {

    private val logger = LoggerFactory.getLogger(SseFanoutConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                "team_sync_started" -> {
                    val event = json.decodeFromString<TeamSyncStartedEvent>(record.value())
                    sseEventBus.emit(SseEvent.TeamSyncStarted(event.teamSlug, event.timestamp))
                }
                "team_sync_complete" -> {
                    val event = json.decodeFromString<TeamSyncCompleteEvent>(record.value())
                    sseEventBus.emit(SseEvent.TeamSyncComplete(event.teamSlug, nowIso()))
                }
                "gcve_sync_complete" -> {
                    val event = json.decodeFromString<GcveSyncCompleteEvent>(record.value())
                    sseEventBus.emit(SseEvent.GcveSyncComplete(event.cveCount, nowIso()))
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
