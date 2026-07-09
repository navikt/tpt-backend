package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.*
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.common.serialization.StringDeserializer
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.*

open class KafkaConsumerService(
    protected val kafkaConfig: KafkaConfig,
    private val groupId: String = "tpt-backend",
    private val autoCommit: Boolean = true,
) {
    private val logger = LoggerFactory.getLogger(KafkaConsumerService::class.java)
    protected var consumer: KafkaConsumer<String, String>? = null
    private var consumerJob: Job? = null
    private var consumerThread: ExecutorCoroutineDispatcher? = null

    protected var isHealthyFlag = true

    open fun start(scope: CoroutineScope) {
        logger.info("Starting Kafka consumer (group=$groupId) for topic: ${kafkaConfig.topic}")

        val dispatcher = newSingleThreadContext("kafka-consumer-$groupId")
        consumerThread = dispatcher

        consumerJob = scope.launch(dispatcher) {
            try {
                consumer = createConsumer()
                consumer?.subscribe(listOf(kafkaConfig.topic))
                logger.info("Kafka consumer subscribed to topic: ${kafkaConfig.topic}")

                while (isActive) {
                    try {
                        val records = consumer?.poll(Duration.ofSeconds(1))
                        records?.let {
                            for (record in it) {
                                processRecord(record)
                            }
                        }
                        isHealthyFlag = true
                    } catch (e: Exception) {
                        logger.error("Error polling Kafka messages", e)
                        isHealthyFlag = false
                        delay(5000)
                    }
                }
            } catch (e: Exception) {
                logger.error("Fatal error in Kafka consumer", e)
                isHealthyFlag = false
            } finally {
                // Close happens on the consumer thread — safe.
                consumer?.close()
                logger.info("Kafka consumer closed")
            }
        }
    }

    protected open suspend fun processRecord(record: ConsumerRecord<String, String>) {
        // Override in subclass to handle records
    }

    /**
     * Commits the current offset synchronously.
     * Always called from processRecord which runs on consumerThread — safe.
     */
    protected fun commitCurrentOffset() {
        consumer?.commitSync()
    }

    open fun stop() {
        logger.info("Stopping Kafka consumer (group=$groupId)")
        consumerJob?.cancel()
        consumerThread?.close()
    }

    open fun isHealthy(): Boolean = isHealthyFlag

    protected open fun createConsumer(): KafkaConsumer<String, String> {
        val props = Properties().apply {
            put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaConfig.brokers)
            put(ConsumerConfig.GROUP_ID_CONFIG, groupId)
            put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
            put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
            put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, autoCommit.toString())
            if (autoCommit) {
                put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, "1000")
            } else {
                // One record at a time: prevents committing unprocessed records in the batch.
                // Extended poll interval: long-running jobs (e.g. full team sync) can exceed
                // the default 5 minutes without triggering an unwanted rebalance.
                put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, "1")
                put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, "${2 * 60 * 60 * 1000}") // 2 hours
            }

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

        logger.info("Creating Kafka consumer (group=$groupId, autoCommit=$autoCommit) with brokers: ${kafkaConfig.brokers}")
        return KafkaConsumer(props)
    }
}
