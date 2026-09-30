package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventPublisher
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.Duration
import java.time.format.DateTimeFormatter

class GcveSyncConsumer(
    kafkaConfig: KafkaConfig,
    private val gcveSyncService: GcveSyncService,
    private val gcveRepository: GcveRepository,
    private val sseEventPublisher: SseEventPublisher,
    pollTimeout: Duration = Duration.ofSeconds(1),
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-gcve-sync", autoCommit = false, pollTimeout = pollTimeout) {

    private val logger = LoggerFactory.getLogger(GcveSyncConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        if (record.key() != KafkaKey.GCVE_SYNC) {
            commitCurrentOffset()
            return
        }
        try {
            val lastSync = gcveRepository.getLastSyncTimestamp()
            val sinceInstant = lastSync ?: Instant.now().minusSeconds(86400)
            val since = sinceInstant.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            val trackedCveIds = gcveRepository.getTrackedCveIds()
            logger.info("Starting GCVE incremental sync since=$since, tracked CVEs: ${trackedCveIds.size}")
            val count = gcveSyncService.performIncrementalSync(since = since, trackedCveIds = trackedCveIds)
            logger.info("GCVE incremental sync complete, upserted $count CVEs")
            val timestamp = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            try {
                sseEventPublisher.publish(SseEvent.GcveSyncComplete(count, timestamp))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.warn("Failed to publish gcve_sync_complete SSE event", e)
            }
            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing gcve_sync command", e)
        }
    }
}
