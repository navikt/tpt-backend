package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventLogRepository
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Duration

class SseEventLogConsumer(
    kafkaConfig: KafkaConfig,
    private val eventLog: SseEventLogRepository,
    pollTimeout: Duration = Duration.ofSeconds(1),
) : KafkaConsumerService(
    kafkaConfig,
    groupId = "tpt-backend-sse-event-log",
    autoCommit = false,
    pollTimeout = pollTimeout,
) {
    private val logger = LoggerFactory.getLogger(SseEventLogConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        val event = try {
            when (record.key()) {
                KafkaKey.GITHUB_VULN_SYNC_STARTED ->
                    json.decodeFromString<GitHubVulnSyncStartedEvent>(record.value())
                        .let { SseEvent.GitHubVulnSyncStarted(it.teams, it.timestamp) }
                KafkaKey.GITHUB_VULN_SYNC_COMPLETE ->
                    json.decodeFromString<GitHubVulnSyncCompleteEvent>(record.value())
                        .let { SseEvent.GitHubVulnSyncComplete(it.teams, it.timestamp) }
                else -> null
            }
        } catch (e: Exception) {
            logger.error("Error decoding SSE event record key=${record.key()}", e)
            commitCurrentOffset()
            return
        }

        try {
            if (event != null) {
                eventLog.publish(event)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // SSE events are only refresh hints for the frontend, so a lost event is acceptable.
            logger.error("Error persisting SSE event record key=${record.key()}, skipping", e)
        }
        commitCurrentOffset()
    }
}
