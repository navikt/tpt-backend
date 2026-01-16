package no.nav.tpt.plugins

import io.ktor.server.application.*
import io.ktor.util.AttributeKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import no.nav.tpt.infrastructure.kafka.KafkaConfig
import no.nav.tpt.infrastructure.kafka.KafkaConsumerService
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("KafkaPlugin")

fun Application.configureKafka() {
    val kafkaConfig = KafkaConfig.fromEnvironment()

    if (kafkaConfig == null) {
        logger.info("Kafka is not configured (KAFKA_BROKERS not set), skipping Kafka consumer initialization")
        return
    }

    val topics = System.getenv("KAFKA_TOPICS")?.split(",")?.map { it.trim() }

    if (topics.isNullOrEmpty()) {
        logger.warn("KAFKA_TOPICS not configured, skipping Kafka consumer initialization")
        return
    }

    logger.info("Initializing Kafka consumer for topics: $topics")

    val kafkaScope = CoroutineScope(SupervisorJob())
    val consumerService = KafkaConsumerService(kafkaConfig, topics)

    consumerService.start(kafkaScope)

    monitor.subscribe(ApplicationStopping) {
        logger.info("Application stopping, shutting down Kafka consumer")
        consumerService.stop()
    }

    attributes.put(KafkaConsumerServiceKey, consumerService)
}

val KafkaConsumerServiceKey = AttributeKey<KafkaConsumerService>("KafkaConsumerService")

val Application.kafkaConsumerService: KafkaConsumerService?
    get() = attributes.getOrNull(KafkaConsumerServiceKey)

