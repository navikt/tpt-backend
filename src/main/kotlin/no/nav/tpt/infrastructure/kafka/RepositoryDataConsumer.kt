package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.datacollector.CheckResult
import no.nav.tpt.infrastructure.github.DockerfileFeaturesMessage
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryMessage
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory

class RepositoryDataConsumer(
    kafkaConfig: KafkaConfig,
    private val repository: GitHubRepository,
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend", autoCommit = true) {

    private val logger = LoggerFactory.getLogger(RepositoryDataConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }
    private var messageCount = 0
    private var lastLogTime = System.currentTimeMillis()

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                "dockerfile_features" -> processDockerfileFeatures(record)
                "CheckResult" -> processCheckResults(record)
                "team_sync", "vuln_data_sync", "gcve_sync" -> return
                else -> processRepositoryMessage(record)
            }

            messageCount++
            val now = System.currentTimeMillis()
            if (now - lastLogTime >= 60000 && messageCount > 0) {
                logger.info("Processed $messageCount repository messages in the last minute")
                messageCount = 0
                lastLogTime = now
            }
        } catch (e: Exception) {
            logger.error("Error processing repository message with key ${record.key()}", e)
        }
    }

    private suspend fun processRepositoryMessage(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<GitHubRepositoryMessage>(record.value())
            try {
                repository.upsertRepositoryData(message)
            } catch (e: Exception) {
                logger.error("Error upserting repository data for ${message.getRepositoryIdentifier()}", e)
            }
        } catch (_: Exception) {
            // Ignore these until we continue the work here.
            //logger.warn("Error parsing repository message: ${record.value()}", e)
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

    private suspend fun processCheckResults(record: ConsumerRecord<String, String>) {
        try {
            val results = json.decodeFromString<List<CheckResult>>(record.value())
            results.filter { it.name == "githubToolingStatus" }.forEach { result ->
                try {
                    val status = when (result) {
                        is CheckResult.AllGood -> "OK"
                        is CheckResult.NeedsWork -> result.reasons.firstOrNull() ?: "error"
                    }
                    repository.updateCodeScanningStatus(result.repo, status)
                } catch (e: Exception) {
                    logger.error("Error updating code scanning status for ${result.repo}", e)
                }
            }
        } catch (e: Exception) {
            logger.error("Error parsing CheckResult message: ${record.value()}", e)
        }
    }
}
