package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.CoroutineScope
import org.slf4j.LoggerFactory

class MockKafkaConsumerService : KafkaConsumerService(
    kafkaConfig = KafkaConfig(
        brokers = "mock:9092",
        certificatePath = "/mock/cert",
        privateKeyPath = "/mock/key",
        caPath = "/mock/ca",
        credstorePassword = "mock",
        keystorePath = "/mock/keystore",
        truststorePath = "/mock/truststore"
    ),
    topics = emptyList()
) {
    private val logger = LoggerFactory.getLogger(MockKafkaConsumerService::class.java)
    private var healthy = true

    override fun start(scope: CoroutineScope) {
        logger.info("Mock Kafka consumer started")
    }

    override fun stop() {
        logger.info("Mock Kafka consumer stopped")
    }

    override fun isHealthy(): Boolean = healthy

    fun setHealthy(healthy: Boolean) {
        this.healthy = healthy
    }
}

