package no.nav.tpt.infrastructure.vulnrichment

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class VulnrichmentClient(
    private val httpClient: HttpClient,
    private val baseUrl: String = "https://api.github.com/repos/cisagov/vulnrichment",
    private val rawBaseUrl: String = "https://raw.githubusercontent.com/cisagov/vulnrichment/main",
) {
    private val logger = LoggerFactory.getLogger(VulnrichmentClient::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private data class GitHubCommit(
        val sha: String,
        val commit: CommitInfo,
        val files: List<CommitFile>? = null,
    )

    @Serializable
    private data class CommitInfo(
        val author: CommitAuthor,
    )

    @Serializable
    private data class CommitAuthor(
        val date: String,
    )

    @Serializable
    private data class CommitFile(
        val filename: String,
        val status: String,
    )

    suspend fun fetchChangedCveData(since: LocalDateTime): List<VulnrichmentData> {
        val sinceStr = since.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        val result = mutableListOf<VulnrichmentData>()
        var page = 1

        while (true) {
            val commits = try {
                val response = httpClient.get("$baseUrl/commits") {
                    parameter("since", sinceStr)
                    parameter("per_page", 100)
                    parameter("page", page)
                }
                if (!response.status.isSuccess()) {
                    logger.warn("GitHub API returned ${response.status} for commits since $sinceStr")
                    break
                }
                json.decodeFromString<List<GitHubCommit>>(response.bodyAsText())
            } catch (e: Exception) {
                logger.error("Failed to fetch Vulnrichment commits: ${e.message}")
                break
            }

            if (commits.isEmpty()) break

            val changedCveFiles = mutableSetOf<String>()
            for (commit in commits) {
                val commitDetail = fetchCommitDetail(commit.sha) ?: continue
                commitDetail.files?.forEach { file ->
                    if (file.filename.matches(Regex(".*/CVE-\\d{4}-\\d+\\.json")) &&
                        file.status != "removed"
                    ) {
                        changedCveFiles.add(file.filename)
                    }
                }
            }

            for (filePath in changedCveFiles) {
                parseCveFile(filePath)?.let { result.add(it) }
            }

            if (commits.size < 100) break
            page++
        }

        return result
    }

    suspend fun fetchCveData(cveId: String): VulnrichmentData? {
        val year = cveId.substringAfter("CVE-").substringBefore("-")
        val filePath = "$year/$cveId.json"
        return parseCveFile(filePath)
    }

    private suspend fun fetchCommitDetail(sha: String): GitHubCommit? {
        return try {
            val response = httpClient.get("$baseUrl/commits/$sha")
            if (!response.status.isSuccess()) return null
            json.decodeFromString<GitHubCommit>(response.bodyAsText())
        } catch (e: Exception) {
            logger.warn("Failed to fetch commit detail for $sha: ${e.message}")
            null
        }
    }

    private suspend fun parseCveFile(filePath: String): VulnrichmentData? {
        return try {
            val response = httpClient.get("$rawBaseUrl/$filePath")
            if (!response.status.isSuccess()) return null
            val cveJson = json.decodeFromString<CveJson5>(response.bodyAsText())
            extractSsvcDecisions(cveJson)
        } catch (e: Exception) {
            logger.warn("Failed to parse Vulnrichment file $filePath: ${e.message}")
            null
        }
    }

    internal fun extractSsvcDecisions(cveJson: CveJson5): VulnrichmentData? {
        val cveId = cveJson.cveMetadata?.cveId ?: return null

        val cisaAdp = cveJson.containers?.adp?.firstOrNull {
            it.providerMetadata?.shortName?.equals("CISA-ADP", ignoreCase = true) == true
        } ?: return null

        val ssvcMetric = cisaAdp.metrics?.firstOrNull { metric ->
            metric.other?.type?.equals("ssvc", ignoreCase = true) == true
        } ?: return null

        val options = ssvcMetric.other?.content?.options ?: return null

        val exploitation = options.firstOrNull { it.containsKey("Exploitation") }?.get("Exploitation")
        val automatable = options.firstOrNull { it.containsKey("Automatable") }?.get("Automatable")
        val technicalImpact = options.firstOrNull { it.containsKey("Technical Impact") }?.get("Technical Impact")

        return VulnrichmentData(
            cveId = cveId,
            exploitationStatus = exploitation?.lowercase(),
            automatable = automatable?.lowercase(),
            technicalImpact = technicalImpact?.lowercase(),
        )
    }
}
