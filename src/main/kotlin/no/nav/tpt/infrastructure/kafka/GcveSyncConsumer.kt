package no.nav.tpt.infrastructure.kafka

import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class GcveSyncConsumer(
    kafkaConfig: KafkaConfig,
    private val gcveSyncService: GcveSyncService,
    private val gcveRepository: GcveRepository,
    private val sseEventBus: SseEventBus,
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-gcve-sync", autoCommit = false) {

    private val logger = LoggerFactory.getLogger(GcveSyncConsumer::class.java)

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        if (record.key() != "gcve_sync") {
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
            sseEventBus.emit(SseEvent.GcveSyncComplete(count, nowIso()))
            commitCurrentOffset()
        } catch (e: Exception) {
            logger.error("Error processing gcve_sync command", e)
        }
    }

    private fun nowIso(): String =
        Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
}
