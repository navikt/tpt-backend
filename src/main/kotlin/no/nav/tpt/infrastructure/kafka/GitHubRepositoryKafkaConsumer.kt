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
                            processRecord(record)
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

    private suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                "dockerfile_features" -> processDockerfileFeatures(record)
                else -> processRepositoryMessage(record)
            }
        } catch (e: Exception) {
            logger.error("Error processing message with key ${record.key()}: ${record.value()}", e)
        }
    }

    private suspend fun processRepositoryMessage(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<GitHubRepositoryMessage>(record.value())
            try {
                repository.upsertRepositoryData(message)
            } catch (e: Exception) {
                logger.error("Error upserting GitHub repository data for ${message.getRepositoryIdentifier()}", e)
            }
        } catch (e: Exception) {
            logger.error("Error parsing GitHub repository message: ${record.value()}", e)
        }
    }

    private suspend fun processDockerfileFeatures(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<DockerfileFeaturesMessage>(record.value())
            try {
                repository.updateDockerfileFeatures(message.repoName, message.usesDistroless)
            } catch (e: Exception) {
                logger.error("Error updating dockerfile features for ${message.repoName}", e)
            }
        } catch (e: Exception) {
            logger.error("Error parsing dockerfile features message: ${record.value()}", e)
        }
    }
}
