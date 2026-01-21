package no.nav.tpt.infrastructure.kafka

import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.github.GitHubRepository
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import java.time.Duration

class GitHubRepositoryKafkaConsumer(
    kafkaConfig: KafkaConfig,
    private val repository: GitHubRepository,
    groupId: String = "tpt-backend"
) : KafkaConsumerService(kafkaConfig, groupId) {

    private val logger = LoggerFactory.getLogger(GitHubRepositoryKafkaConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }
    private var consumerJob: Job? = null

    override fun start(scope: CoroutineScope) {
        logger.info("Starting Kafka consumer for GitHub repositories on topic: ${kafkaConfig.topic}")

        consumerJob = scope.launch(Dispatchers.IO) {
            try {
                consumer = createConsumer()
                consumer?.subscribe(listOf(kafkaConfig.topic))
                logger.info("GitHub repository consumer subscribed to topic: ${kafkaConfig.topic}")

                while (isActive) {
                    try {
                        val records = consumer?.poll(Duration.ofSeconds(1))
                        records?.forEach { record ->
                            processRecord(record, this)
                        }
                        isHealthyFlag = true
                    } catch (e: Exception) {
                        logger.error("Error polling Kafka messages", e)
                        isHealthyFlag = false
                        delay(5000)
                    }
                }
            } catch (e: Exception) {
                logger.error("Fatal error in GitHub repository Kafka consumer", e)
                isHealthyFlag = false
            } finally {
                consumer?.close()
                logger.info("GitHub repository Kafka consumer closed")
            }
        }
    }

    private fun processRecord(record: ConsumerRecord<String, String>, scope: CoroutineScope) {
        logger.info(
            "Received GitHub repository message - Topic: ${record.topic()}, " +
            "Partition: ${record.partition()}, " +
            "Offset: ${record.offset()}, " +
            "Key: ${record.key()}"
        )

        try {
            val message = json.decodeFromString<GitHubRepositoryMessage>(record.value())
            logger.info(
                "Parsed GitHub repository message: repositoryName=${message.nameWithOwner}, " +
                "teams=${message.naisTeams?.joinToString() ?: "none"}, " +
                "vulnerabilities=${message.vulnerabilities?.size ?: 0}"
            )

            scope.launch(Dispatchers.IO) {
                try {
                    repository.upsertRepositoryData(message)
                    logger.info("Successfully upserted GitHub repository data for: ${message.nameWithOwner}")
                } catch (e: Exception) {
                    logger.error("Error upserting GitHub repository data for ${message.nameWithOwner}", e)
                }
            }
        } catch (e: Exception) {
            logger.error("Error parsing GitHub repository message: ${record.value()}", e)
        }
    }
}
