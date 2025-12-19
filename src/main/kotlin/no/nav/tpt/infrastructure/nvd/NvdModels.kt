package no.nav.tpt.infrastructure.nvd

import kotlinx.serialization.Serializable
import java.time.LocalDate
import java.time.LocalDateTime

// API Response Models (match NVD API v2.0 schema)

@Serializable
data class NvdResponse(
    val resultsPerPage: Int,
    val startIndex: Int,
    val totalResults: Int,
    val format: String,
    val version: String,
    val timestamp: String,
    val vulnerabilities: List<VulnerabilityItem>
)

@Serializable
data class VulnerabilityItem(
    val cve: CveItem
)

@Serializable
data class CveItem(
    val id: String,
    val sourceIdentifier: String?,
    val published: String,
    val lastModified: String,
    val vulnStatus: String?,

    // CISA KEV fields (embedded in NVD API!)
    val cisaExploitAdd: String?,
    val cisaActionDue: String?,
    val cisaRequiredAction: String?,
    val cisaVulnerabilityName: String?,

    val descriptions: List<CveDescription>?,
    val metrics: CveMetrics?,
    val references: List<CveReference>?,
    val weaknesses: List<CveWeakness>?
)

@Serializable
data class CveDescription(
    val lang: String,
    val value: String
)

@Serializable
data class CveMetrics(
    val cvssMetricV31: List<CvssMetricV31>? = null,
    val cvssMetricV30: List<CvssMetricV30>? = null,
    val cvssMetricV2: List<CvssMetricV2>? = null
)

@Serializable
data class CvssMetricV31(
    val source: String,
    val type: String,
    val cvssData: CvssDataV31
)

@Serializable
data class CvssDataV31(
    val version: String,
    val vectorString: String,
    val baseScore: Double,
    val baseSeverity: String
)

@Serializable
data class CvssMetricV30(
    val source: String,
    val type: String,
    val cvssData: CvssDataV30
)

@Serializable
data class CvssDataV30(
    val version: String,
    val vectorString: String,
    val baseScore: Double,
    val baseSeverity: String
)

@Serializable
data class CvssMetricV2(
    val source: String,
    val type: String,
    val cvssData: CvssDataV2
)

@Serializable
data class CvssDataV2(
    val version: String,
    val vectorString: String,
    val baseScore: Double
)

@Serializable
data class CveReference(
    val url: String,
    val source: String?,
    val tags: List<String>?
)

@Serializable
data class CveWeakness(
    val source: String,
    val type: String,
    val description: List<WeaknessDescription>
)

@Serializable
data class WeaknessDescription(
    val lang: String,
    val value: String  // e.g., "CWE-120"
)

// Domain Model (what we store in database)

data class NvdCveData(
    val cveId: String,
    val sourceIdentifier: String?,
    val vulnStatus: String?,
    val publishedDate: LocalDateTime,
    val lastModifiedDate: LocalDateTime,

    // CISA KEV fields
    val cisaExploitAdd: LocalDate?,
    val cisaActionDue: LocalDate?,
    val cisaRequiredAction: String?,
    val cisaVulnerabilityName: String?,

    // CVSS scores (prefer v3.1 > v3.0 > v2.0)
    val cvssV31Score: Double?,
    val cvssV31Severity: String?,
    val cvssV30Score: Double?,
    val cvssV30Severity: String?,
    val cvssV2Score: Double?,
    val cvssV2Severity: String?,

    // Content
    val description: String?,
    val references: List<String>,
    val cweIds: List<String>,

    // Computed fields
    val daysOld: Long,
    val daysSinceModified: Long,
    val hasExploitReference: Boolean,
    val hasPatchReference: Boolean
)

