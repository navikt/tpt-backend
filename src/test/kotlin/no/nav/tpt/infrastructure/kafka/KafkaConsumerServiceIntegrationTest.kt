package no.nav.tpt.infrastructure.kafka

import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringDeserializer
import org.apache.kafka.common.serialization.StringSerializer
import org.junit.jupiter.api.Test
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.time.Duration
import java.util.*
import kotlin.test.assertEquals

@Testcontainers
class KafkaConsumerServiceIntegrationTest {

    companion object {
        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
    }

    private val testTopic = "test-topic"

    @Test
    fun `should receive messages from Kafka`() {
        val bootstrapServers = kafkaContainer.bootstrapServers

        val producer = KafkaProducer<String, String>(
            Properties().apply {
                put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
                put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
                put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
                put(ProducerConfig.ACKS_CONFIG, "all")
                put(ProducerConfig.RETRIES_CONFIG, 3)
            }
        )
        val consumer = KafkaConsumer<String, String>(
            Properties().apply {
                put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
                put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.GROUP_ID_CONFIG, "test-group")
                put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
                put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true")
            }
        )
        consumer.subscribe(listOf(testTopic))

        val testMessages = listOf(
            """{"type": "vulnerability", "data": "CVE-2024-1234"}""",
            """{"type": "application", "data": "my-app"}""",
            """{"type": "team", "data": "my-team"}""",
        )

        testMessages.forEach { message ->
            producer.send(ProducerRecord(testTopic, "test-key", message)).get()
        }
        producer.close()

        val messages = consumer.poll(Duration.ofSeconds(1))
        assertEquals(3, messages.count())
        consumer.close()
    }
}
