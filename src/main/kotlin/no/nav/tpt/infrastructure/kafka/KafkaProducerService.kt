package no.nav.tpt.infrastructure.kafka

import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringSerializer
import org.slf4j.LoggerFactory
import java.util.Properties

open class KafkaProducerService(private val kafkaConfig: KafkaConfig) : SyncPublisher {
    private val logger = LoggerFactory.getLogger(KafkaProducerService::class.java)
    private val producer: KafkaProducer<String, String> = createProducer()

    override fun publish(key: String, value: String) {
        try {
            val record = ProducerRecord(kafkaConfig.topic, key, value)
            producer.send(record) { metadata, exception ->
                if (exception != null) {
                    logger.error("Failed to publish message with key=$key to topic=${kafkaConfig.topic}", exception)
                } else {
                    logger.debug("Published message key=$key to topic=${metadata.topic()} partition=${metadata.partition()} offset=${metadata.offset()}")
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to publish message with key=$key", e)
        }
    }

    open fun close() {
        producer.close()
    }

    private fun createProducer(): KafkaProducer<String, String> {
        val props = Properties().apply {
            put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaConfig.brokers)
            put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.ACKS_CONFIG, "all")
            put(ProducerConfig.RETRIES_CONFIG, 3)

            if (kafkaConfig.keystorePath.isNotEmpty()) {
                put("security.protocol", "SSL")
                put("ssl.keystore.type", "PKCS12")
                put("ssl.keystore.location", kafkaConfig.keystorePath)
                put("ssl.keystore.password", kafkaConfig.credstorePassword)
                put("ssl.truststore.type", "JKS")
                put("ssl.truststore.location", kafkaConfig.truststorePath)
                put("ssl.truststore.password", kafkaConfig.credstorePassword)
                put("ssl.key.password", kafkaConfig.credstorePassword)
            }
        }

        logger.info("Creating Kafka producer with brokers: ${kafkaConfig.brokers}")
        return KafkaProducer(props)
    }
}
