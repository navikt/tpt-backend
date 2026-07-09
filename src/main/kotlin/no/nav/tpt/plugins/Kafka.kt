package no.nav.tpt.plugins

import io.ktor.server.application.*
import io.ktor.util.AttributeKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import no.nav.tpt.infrastructure.kafka.GitHubRepositoryKafkaConsumer
import no.nav.tpt.infrastructure.kafka.KafkaConfig
import no.nav.tpt.infrastructure.kafka.KafkaConsumerService
import no.nav.tpt.infrastructure.kafka.KafkaProducerService
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("KafkaPlugin")

fun Application.configureKafka() {
    val kafkaConfig = KafkaConfig.fromEnvironment()

    if (kafkaConfig == null) {
        logger.info("Kafka is not configured (KAFKA_BROKERS not set), skipping Kafka initialization")
        return
    }

    logger.info("Initializing Kafka consumer and producer for topic: ${kafkaConfig.topic}")

    val producer = KafkaProducerService(kafkaConfig)
    attributes.put(KafkaProducerServiceKey, producer)

    val kafkaScope = CoroutineScope(SupervisorJob())
    val consumerService = GitHubRepositoryKafkaConsumer(
        kafkaConfig = kafkaConfig,
        repository = dependencies.gitHubRepository,
        vulnerabilityTeamSyncService = dependencies.vulnerabilityTeamSyncService,
        vulnerabilityDataSyncJob = dependencies.vulnerabilityDataSyncJob,
        gcveSyncService = dependencies.gcveSyncService,
        gcveRepository = dependencies.gcveRepository,
        sseEventBus = dependencies.sseEventBus,
    )

    consumerService.start(kafkaScope)

    monitor.subscribe(ApplicationStopping) {
        logger.info("Application stopping, shutting down Kafka consumer and producer")
        consumerService.stop()
        producer.close()
    }

    attributes.put(KafkaConsumerServiceKey, consumerService)
}

val KafkaConsumerServiceKey = AttributeKey<KafkaConsumerService>("KafkaConsumerService")
val KafkaProducerServiceKey = AttributeKey<KafkaProducerService>("KafkaProducerService")

val Application.kafkaConsumerService: KafkaConsumerService?
    get() = attributes.getOrNull(KafkaConsumerServiceKey)
