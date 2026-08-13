package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.gcve.GcveSyncService
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
    private val kafkaProducer: SyncPublisher,
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
            kafkaProducer.publish(KafkaKey.GCVE_SYNC_COMPLETE, json.encodeToString(GcveSyncCompleteEvent(count)))
            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing gcve_sync command", e)
        }
    }
}
