package no.nav.tpt.infrastructure.kafka

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.datacollector.CheckResult
import no.nav.tpt.infrastructure.datacollector.DatacollectorRepository
import no.nav.tpt.infrastructure.github.DockerfileFeaturesMessage
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryMessage
import no.nav.tpt.metrics.TPTMetrics
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory

import java.time.Duration

class DataCollectorConsumer(
    kafkaConfig: KafkaConfig,
    private val gitHubRepository: GitHubRepository,
    private val dataCollectorRepository: DatacollectorRepository,
    pollTimeout: Duration = Duration.ofSeconds(1),
) : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend", autoCommit = true, pollTimeout = pollTimeout) {

    private val logger = LoggerFactory.getLogger(DataCollectorConsumer::class.java)
    private val json = Json { ignoreUnknownKeys = true }
    private var messageCount = 0
    private var lastLogTime = System.currentTimeMillis()

    override suspend fun processRecord(record: ConsumerRecord<String, String>) {
        try {
            when (record.key()) {
                "dockerfile_features" -> processDockerfileFeatures(record)
                "CheckResult" -> processCheckResults(record)
                KafkaKey.TEAM_SYNC, KafkaKey.TEAM_SYNC_STARTED, KafkaKey.TEAM_SYNC_COMPLETE,
                KafkaKey.VULN_DATA_SYNC, KafkaKey.GCVE_SYNC, KafkaKey.GCVE_SYNC_COMPLETE -> return
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
            logger.error("Error processing data collector message with key ${record.key()}", e)
        }
    }

    private suspend fun processRepositoryMessage(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<GitHubRepositoryMessage>(record.value())
            try {
                gitHubRepository.upsertRepositoryData(message)
            } catch (e: Exception) {
                logger.error("Error upserting repository data for ${message.getRepositoryIdentifier()}", e)
            }
        } catch (e: Exception) {
            // Ignore these until we continue the work here.
            logger.warn("Error parsing repository message: ${record.value()}", e)
        }
    }

    private suspend fun processDockerfileFeatures(record: ConsumerRecord<String, String>) {
        try {
            val message = json.decodeFromString<DockerfileFeaturesMessage>(record.value())
            try {
                gitHubRepository.updateDockerfileFeatures(message.repoName, message.usesDistroless)
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
            storeCodeScanningStatus(results.filter { it.name == "githubToolingStatus" })
            storeCheckResults(results)
        } catch (e: Exception) {
            logger.error("Error parsing CheckResult message: ${record.value()}", e)
        }
    }

    private suspend fun storeCodeScanningStatus(checkResults: List<CheckResult>) {
        checkResults.forEach { result ->
            try {
                val status = when (result) {
                    is CheckResult.AllGood -> "OK"
                    is CheckResult.NeedsWork -> result.reasons.firstOrNull() ?: "error"
                }
                val nameWithOwner = if ('/' in result.repo) result.repo else "navikt/${result.repo}"
                gitHubRepository.updateCodeScanningStatus(nameWithOwner, status)
            } catch (e: Exception) {
                logger.error("Error updating code scanning status for ${result.repo}", e)
            }
        }
    }

    private suspend fun storeCheckResults(checkResults: List<CheckResult>) {
        checkResults.forEach { result ->
            try {
//                dataCollectorRepository.insert(result)
//                TPTMetrics.checksPersisted()
            } catch (e: Exception) {
                logger.error("Error saving check result for ${result.repo}", e)
                TPTMetrics.checksPersistingFailed()
            }
        }
    }
}
