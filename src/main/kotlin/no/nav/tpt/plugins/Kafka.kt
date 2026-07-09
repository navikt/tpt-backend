package no.nav.tpt.plugins

import io.ktor.server.application.*
import io.ktor.util.AttributeKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import no.nav.tpt.infrastructure.kafka.*
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("KafkaPlugin")

fun Application.configureKafka() {
    val kafkaConfig = KafkaConfig.fromEnvironment()

    if (kafkaConfig == null) {
        logger.info("Kafka is not configured (KAFKA_BROKERS not set), skipping Kafka initialization")
        return
    }

    val producer = dependencies.kafkaProducerService ?: run {
        logger.warn("Kafka is configured but kafkaProducerService is null — skipping Kafka initialization")
        return
    }

    logger.info("Initializing Kafka consumers for topic: ${kafkaConfig.topic}")

    val consumers = listOf(
        RepositoryDataConsumer(
            kafkaConfig = kafkaConfig,
            repository = dependencies.gitHubRepository,
        ),
        TeamSyncConsumer(
            kafkaConfig = kafkaConfig,
            vulnerabilityTeamSyncService = dependencies.vulnerabilityTeamSyncService,
            sseEventBus = dependencies.sseEventBus,
        ),
        VulnerabilityDataSyncConsumer(
            kafkaConfig = kafkaConfig,
            vulnerabilityDataSyncJob = dependencies.vulnerabilityDataSyncJob,
        ),
        GcveSyncConsumer(
            kafkaConfig = kafkaConfig,
            gcveSyncService = dependencies.gcveSyncService,
            gcveRepository = dependencies.gcveRepository,
            sseEventBus = dependencies.sseEventBus,
        ),
    )

    consumers.forEach { it.start(CoroutineScope(SupervisorJob())) }

    monitor.subscribe(ApplicationStopping) {
        logger.info("Application stopping, shutting down Kafka consumers and producer")
        consumers.forEach { it.stop() }
        producer.close()
    }

    attributes.put(KafkaConsumersKey, consumers)
}

val KafkaConsumersKey = AttributeKey<List<KafkaConsumerService>>("KafkaConsumers")

val Application.kafkaConsumers: List<KafkaConsumerService>?
    get() = attributes.getOrNull(KafkaConsumersKey)
