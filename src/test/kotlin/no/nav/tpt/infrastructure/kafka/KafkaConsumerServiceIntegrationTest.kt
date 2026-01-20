package no.nav.tpt.infrastructure.kafka

import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringDeserializer
import org.apache.kafka.common.serialization.StringSerializer
import org.slf4j.LoggerFactory
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.time.Duration
import java.util.*
import kotlin.test.*

class KafkaConsumerServiceIntegrationTest {
    private val logger = LoggerFactory.getLogger(KafkaConsumerServiceIntegrationTest::class.java)
    private lateinit var kafkaContainer: KafkaContainer
    private lateinit var bootstrapServers: String
    private val testTopic = "test-topic"

    @BeforeTest
    fun setup() {
        kafkaContainer = KafkaContainer(
            DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
        kafkaContainer.start()

        bootstrapServers = kafkaContainer.bootstrapServers
        logger.info("Kafka container started on: $bootstrapServers")
    }

    @AfterTest
    fun teardown() {
        kafkaContainer.stop()
    }

    @Test
    fun `should receive messages from Kafka`() {
        val producer = createTestProducer(bootstrapServers)
        val consumer = createTestConsumer(bootstrapServers)
        consumer.subscribe(listOf(testTopic))

        val testMessages = listOf(
            """{"type": "vulnerability", "data": "CVE-2024-1234"}""",
            """{"type": "application", "data": "my-app"}""",
            """{"type": "team", "data": "my-team"}"""
        )

        testMessages.forEach { message ->
            val record = ProducerRecord(testTopic, "test-key", message)
            producer.send(record).get()
            logger.info("Sent message: $message")
        }

        producer.close()

        // Check if messages are received by the consumer
        val messages = consumer.poll(Duration.ofSeconds(1))


        assertEquals(3, messages.count())
        consumer.close()
    }


    private fun createTestProducer(bootstrapServers: String): KafkaProducer<String, String> {
        val props = Properties().apply {
            put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
            put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.ACKS_CONFIG, "all")
            put(ProducerConfig.RETRIES_CONFIG, 3)
        }
        return KafkaProducer(props)
    }

    private fun createTestConsumer(bootstrapServers: String): KafkaConsumer<String, String> {
        val props = Properties().apply {
            put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
            put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
            put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
            put(ConsumerConfig.GROUP_ID_CONFIG, "test-group")
            put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true")
        }
        return KafkaConsumer(props)
    }
}

