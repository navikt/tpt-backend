package no.nav.tpt.infrastructure.nvd

import java.time.LocalDate
import java.time.LocalDateTime

/**
 * Test data builders for NVD API responses following official schema at:
 * docs/schemas/cve_api_json_2.0.schema
 */
object NvdTestDataBuilder {

    fun buildCveItem(
        id: String = "CVE-2024-1234",
        sourceIdentifier: String = "cve@mitre.org",
        vulnStatus: String = "Analyzed",
        published: String = "2024-01-15T10:00:00.000Z",
        lastModified: String = "2024-01-16T12:30:00.000Z",
        cisaExploitAdd: String? = null,
        cisaActionDue: String? = null,
        cisaRequiredAction: String? = null,
        cisaVulnerabilityName: String? = null,
        descriptions: List<CveDescription> = listOf(
            CveDescription("en", "A buffer overflow vulnerability exists in the application.")
        ),
        cvssV31: CvssMetricV31? = buildCvssV31Metric(),
        cvssV30: CvssMetricV30? = null,
        cvssV2: CvssMetricV2? = null,
        ssvcMetric: SsvcMetric? = null,
        references: List<CveReference> = listOf(
            CveReference("https://example.com/advisory", "vendor@example.com", listOf("Vendor Advisory"))
        ),
        weaknesses: List<CveWeakness>? = listOf(
            CveWeakness("nvd@nist.gov", "Primary", listOf(WeaknessDescription("en", "CWE-120")))
        )
    ): CveItem {
        return CveItem(
            id = id,
            sourceIdentifier = sourceIdentifier,
            published = published,
            lastModified = lastModified,
            vulnStatus = vulnStatus,
            cisaExploitAdd = cisaExploitAdd,
            cisaActionDue = cisaActionDue,
            cisaRequiredAction = cisaRequiredAction,
            cisaVulnerabilityName = cisaVulnerabilityName,
            descriptions = descriptions,
            metrics = CveMetrics(
                cvssMetricV31 = cvssV31?.let { listOf(it) },
                cvssMetricV30 = cvssV30?.let { listOf(it) },
                cvssMetricV2 = cvssV2?.let { listOf(it) },
                ssvcV203 = ssvcMetric?.let { listOf(it) }
            ),
            references = references,
            weaknesses = weaknesses
        )
    }

    fun buildSsvcMetric(
        source: String = "134c704f-9b21-4f2e-91b3-4a467353bcc0",
        exploitation: String = "none",
        automatable: String = "no",
        technicalImpact: String = "partial",
        role: String = "CISA Coordinator"
    ): SsvcMetric {
        return SsvcMetric(
            source = source,
            ssvcData = SsvcData(
                options = listOf(
                    mapOf("exploitation" to exploitation),
                    mapOf("automatable" to automatable),
                    mapOf("technicalImpact" to technicalImpact)
                ),
                role = role
            )
        )
    }

    fun buildCvssV31Metric(
        source: String = "nvd@nist.gov",
        type: String = "Primary",
        vectorString: String = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        baseScore: Double = 9.8,
        baseSeverity: String = "CRITICAL"
    ): CvssMetricV31 {
        return CvssMetricV31(
            source = source,
            type = type,
            cvssData = CvssDataV31(
                version = "3.1",
                vectorString = vectorString,
                baseScore = baseScore,
                baseSeverity = baseSeverity
            )
        )
    }

    fun buildCvssV30Metric(
        source: String = "nvd@nist.gov",
        type: String = "Primary",
        vectorString: String = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        baseScore: Double = 9.8,
        baseSeverity: String = "CRITICAL"
    ): CvssMetricV30 {
        return CvssMetricV30(
            source = source,
            type = type,
            cvssData = CvssDataV30(
                version = "3.0",
                vectorString = vectorString,
                baseScore = baseScore,
                baseSeverity = baseSeverity
            )
        )
    }

    fun buildCvssV2Metric(
        source: String = "nvd@nist.gov",
        type: String = "Primary",
        vectorString: String = "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        baseScore: Double = 7.5
    ): CvssMetricV2 {
        return CvssMetricV2(
            source = source,
            type = type,
            cvssData = CvssDataV2(
                version = "2.0",
                vectorString = vectorString,
                baseScore = baseScore
            )
        )
    }

    fun buildNvdResponse(
        vulnerabilities: List<VulnerabilityItem>,
        resultsPerPage: Int = vulnerabilities.size,
        startIndex: Int = 0,
        totalResults: Int = vulnerabilities.size
    ): NvdResponse {
        return NvdResponse(
            resultsPerPage = resultsPerPage,
            startIndex = startIndex,
            totalResults = totalResults,
            format = "NVD_CVE",
            version = "2.0",
            timestamp = LocalDateTime.now().toString(),
            vulnerabilities = vulnerabilities
        )
    }

    fun buildVulnerabilityItem(cve: CveItem): VulnerabilityItem {
        return VulnerabilityItem(cve)
    }

    fun buildNvdCveData(
        cveId: String = "CVE-2024-1234",
        sourceIdentifier: String? = "cve@mitre.org",
        vulnStatus: String? = "Analyzed",
        publishedDate: LocalDateTime = LocalDateTime.of(2024, 1, 15, 10, 0),
        lastModifiedDate: LocalDateTime = LocalDateTime.of(2024, 1, 16, 12, 30),
        cisaExploitAdd: LocalDate? = null,
        cisaActionDue: LocalDate? = null,
        cisaRequiredAction: String? = null,
        cisaVulnerabilityName: String? = null,
        cvssV31Score: Double? = 9.8,
        cvssV31Severity: String? = "CRITICAL",
        cvssV30Score: Double? = null,
        cvssV30Severity: String? = null,
        cvssV2Score: Double? = null,
        cvssV2Severity: String? = null,
        description: String? = "A buffer overflow vulnerability exists in the application.",
        references: List<String> = listOf("https://example.com/advisory"),
        cweIds: List<String> = listOf("CWE-120"),
        hasExploitReference: Boolean = false,
        hasPatchReference: Boolean = false,
        nvdSsvcExploitation: String? = null,
        nvdSsvcAutomatable: String? = null,
        nvdSsvcTechnicalImpact: String? = null
    ): NvdCveData {
        val now = LocalDateTime.now()
        return NvdCveData(
            cveId = cveId,
            sourceIdentifier = sourceIdentifier,
            vulnStatus = vulnStatus,
            publishedDate = publishedDate,
            lastModifiedDate = lastModifiedDate,
            cisaExploitAdd = cisaExploitAdd,
            cisaActionDue = cisaActionDue,
            cisaRequiredAction = cisaRequiredAction,
            cisaVulnerabilityName = cisaVulnerabilityName,
            cvssV31Score = cvssV31Score,
            cvssV31Severity = cvssV31Severity,
            cvssV30Score = cvssV30Score,
            cvssV30Severity = cvssV30Severity,
            cvssV2Score = cvssV2Score,
            cvssV2Severity = cvssV2Severity,
            description = description,
            references = references,
            cweIds = cweIds,
            daysOld = java.time.temporal.ChronoUnit.DAYS.between(publishedDate, now),
            daysSinceModified = java.time.temporal.ChronoUnit.DAYS.between(lastModifiedDate, now),
            hasExploitReference = hasExploitReference,
            hasPatchReference = hasPatchReference,
            nvdSsvcExploitation = nvdSsvcExploitation,
            nvdSsvcAutomatable = nvdSsvcAutomatable,
            nvdSsvcTechnicalImpact = nvdSsvcTechnicalImpact
        )
    }

    // Preset test scenarios

    fun buildCriticalKevCve(): CveItem {
        return buildCveItem(
            id = "CVE-2024-9999",
            vulnStatus = "Analyzed",
            cisaExploitAdd = "2024-01-20",
            cisaActionDue = "2024-02-10",
            cisaRequiredAction = "Apply updates per vendor instructions",
            cisaVulnerabilityName = "Critical Authentication Bypass",
            cvssV31 = buildCvssV31Metric(baseScore = 9.8, baseSeverity = "CRITICAL"),
            references = listOf(
                CveReference("https://example.com/exploit", "researcher@example.com", listOf("Exploit")),
                CveReference("https://example.com/patch", "vendor@example.com", listOf("Patch"))
            ),
            weaknesses = listOf(
                CveWeakness("nvd@nist.gov", "Primary", listOf(WeaknessDescription("en", "CWE-287")))
            )
        )
    }

    fun buildHighSeverityWithExploit(): CveItem {
        return buildCveItem(
            id = "CVE-2024-8888",
            vulnStatus = "Analyzed",
            cvssV31 = buildCvssV31Metric(baseScore = 7.5, baseSeverity = "HIGH"),
            references = listOf(
                CveReference("https://github.com/exploit", "researcher@example.com", listOf("Exploit", "Third Party Advisory"))
            ),
            weaknesses = listOf(
                CveWeakness("nvd@nist.gov", "Primary", listOf(WeaknessDescription("en", "CWE-79")))
            )
        )
    }

    fun buildMediumSeverityWithPatch(): CveItem {
        return buildCveItem(
            id = "CVE-2024-7777",
            vulnStatus = "Analyzed",
            cvssV31 = buildCvssV31Metric(baseScore = 5.3, baseSeverity = "MEDIUM"),
            references = listOf(
                CveReference("https://example.com/patch", "vendor@example.com", listOf("Patch", "Vendor Advisory"))
            ),
            weaknesses = listOf(
                CveWeakness("nvd@nist.gov", "Primary", listOf(WeaknessDescription("en", "CWE-200")))
            )
        )
    }

    fun buildLowSeverityNoKev(): CveItem {
        return buildCveItem(
            id = "CVE-2024-6666",
            vulnStatus = "Analyzed",
            cvssV31 = buildCvssV31Metric(baseScore = 3.7, baseSeverity = "LOW"),
            weaknesses = listOf(
                CveWeakness("nvd@nist.gov", "Primary", listOf(WeaknessDescription("en", "CWE-400")))
            )
        )
    }

    fun buildCveWithMultipleCvssVersions(): CveItem {
        return buildCveItem(
            id = "CVE-2024-5555",
            cvssV31 = buildCvssV31Metric(baseScore = 7.8, baseSeverity = "HIGH"),
            cvssV30 = buildCvssV30Metric(baseScore = 7.5, baseSeverity = "HIGH"),
            cvssV2 = buildCvssV2Metric(baseScore = 6.8)
        )
    }

    fun buildRejectedCve(): CveItem {
        return buildCveItem(
            id = "CVE-2024-4444",
            vulnStatus = "Rejected",
            descriptions = listOf(
                CveDescription("en", "** REJECT ** This CVE has been rejected by the CVE Program.")
            ),
            cvssV31 = null,
            references = emptyList(),
            weaknesses = emptyList()
        )
    }
}

