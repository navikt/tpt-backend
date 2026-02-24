package no.nav.tpt.infrastructure.remediation

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import no.nav.tpt.domain.remediation.RemediationRequest
import no.nav.tpt.domain.remediation.RemediationService
import no.nav.tpt.infrastructure.ai.AiClient
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.nvd.NvdCveData
import no.nav.tpt.infrastructure.nvd.NvdRepository
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(RemediationServiceImpl::class.java)

private val SYSTEM_PROMPT = """
You are a security engineer. Your task is to generate a clear, actionable remediation guide for a specific software vulnerability affecting a workload.

Only use information provided below. Do not invent package versions, configurations, or upgrade paths that are not established knowledge for this CVE.

If authoritative remediation information is not available for this CVE, clearly state that and advise the user to consult the package maintainer's security advisory.
""".trimIndent()

class RemediationServiceImpl(
    private val aiClient: AiClient,
    private val cacheRepository: RemediationCacheRepository,
    private val nvdRepository: NvdRepository,
    private val epssService: EpssService,
    private val kevService: KevService
) : RemediationService {

    override fun streamRemediation(request: RemediationRequest): Flow<String> = flow {
        val cached = cacheRepository.getCached(request.cveId, request.packageEcosystem)
        if (cached != null) {
            emit(cached.remediationText)
            return@flow
        }

        val nvdData = nvdRepository.getCveData(request.cveId)
        val epssScores = epssService.getEpssScores(listOf(request.cveId))
        val epssScore = epssScores[request.cveId]
        val kevCatalog = kevService.getKevCatalog()
        val isKev = kevCatalog.vulnerabilities.any { it.cveID == request.cveId }

        val userPrompt = buildUserPrompt(request, nvdData, epssScore?.epss, epssScore?.percentile, isKev)

        val accumulated = StringBuilder()
        aiClient.streamCompletion(SYSTEM_PROMPT, userPrompt).collect { chunk ->
            accumulated.append(chunk)
            emit(chunk)
        }

        try {
            cacheRepository.saveCache(request.cveId, request.packageEcosystem, accumulated.toString())
        } catch (e: Exception) {
            logger.warn("Failed to cache remediation for ${request.cveId}: ${e.message}")
        }
    }
    private fun buildUserPrompt(
        request: RemediationRequest,
        nvdData: NvdCveData?,
        epssScore: String?,
        epssPercentile: String?,
        isKev: Boolean
    ): String {
        val cvssScore = (nvdData?.cvssV31Score ?: nvdData?.cvssV30Score ?: nvdData?.cvssV2Score)
            ?.let { String.format("%.1f", it) } ?: "N/A"
        val description = nvdData?.description ?: "No description available."
        val epssLine = if (epssScore != null && epssPercentile != null) {
            val percentileNum = (epssPercentile.toDoubleOrNull() ?: 0.0) * 100
            "$epssScore (${"%.0f".format(percentileNum)}th percentile — probability of exploitation within 30 days)"
        } else {
            "N/A"
        }

        return """
Vulnerability:
  CVE ID: ${request.cveId}
  Description: $description
  CVSS Score: $cvssScore
  Known Exploited Vulnerability (CISA KEV): ${if (isKev) "yes" else "no"}
  EPSS Score: $epssLine

Affected workload:
  Application: ${request.workloadName}
  Environment: ${request.environment}
  Package: ${request.packageName}
  Ecosystem: ${request.packageEcosystem}

Provide a structured response with:
1. Risk summary (2-3 sentences on what is at risk and why it matters)
2. Recommended remediation steps (numbered, actionable)
3. Known upgrade path or patch (specific version if known, otherwise note that it should be verified)
4. Any interim mitigations if an upgrade is not immediately possible
        """.trimIndent()
    }
}
