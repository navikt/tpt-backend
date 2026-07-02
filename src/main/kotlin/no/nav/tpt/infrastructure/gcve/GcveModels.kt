package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.LocalDateTime
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

@Serializable
data class GcveCveRecord(
    val dataType: String,
    val dataVersion: String,
    val cveMetadata: GcveCveMetadata,
    val containers: GcveContainers,
) {
    companion object {
        fun toDomainModel(record: GcveCveRecord): GcveCveData {
            val cna = record.containers.cna
            val cisaAdp = record.containers.adp
                ?.find { it.providerMetadata?.shortName == "CISA-ADP" }

            val description = cna.descriptions
                .firstOrNull { it.lang == "en" }
                ?.value

            val cweIds = cna.problemTypes
                ?.flatMap { it.descriptions }
                ?.mapNotNull { it.cweId }
                ?: emptyList()

            val references = cna.references.map { it.url }

            val hasExploitReference = cna.references.any { ref ->
                ref.tags?.any { it.equals("Exploit", ignoreCase = true) } == true
            }
            val hasPatchReference = cna.references.any { ref ->
                ref.tags?.any { it.equals("Patch", ignoreCase = true) } == true
            }

            val adpCvssV31 = cisaAdp?.metrics?.mapNotNull { it.cvssV3_1 }?.firstOrNull()
            val cnaCvssV31 = cna.metrics?.mapNotNull { it.cvssV3_1 }?.firstOrNull()
            val bestCvssV31 = adpCvssV31 ?: cnaCvssV31

            val cnaCvssV40 = cna.metrics?.mapNotNull { it.cvssV4_0 }?.firstOrNull()
            val adpCvssV40 = cisaAdp?.metrics?.mapNotNull { it.cvssV4_0 }?.firstOrNull()
            val bestCvssV40 = adpCvssV40 ?: cnaCvssV40

            val ssvc = cisaAdp?.metrics
                ?.mapNotNull { it.other }
                ?.find { it.type == "ssvc" }
                ?.content

            val ssvcOptions = ssvc?.options ?: emptyList()
            val ssvcExploitation = ssvcOptions
                .firstOrNull { it.containsKey("Exploitation") }
                ?.get("Exploitation")?.lowercase()
            val ssvcAutomatable = ssvcOptions
                .firstOrNull { it.containsKey("Automatable") }
                ?.get("Automatable")?.lowercase()
            val ssvcTechnicalImpact = ssvcOptions
                .firstOrNull { it.containsKey("Technical Impact") }
                ?.get("Technical Impact")?.lowercase()

            val kevMetric = cisaAdp?.metrics
                ?.mapNotNull { it.other }
                ?.find { it.type == "kev" }
                ?.content

            val publishedDate = record.cveMetadata.datePublished?.let { parseTimestamp(it) }
            val lastUpdatedDate = record.cveMetadata.dateUpdated?.let { parseTimestamp(it) }
            val now = LocalDateTime.now()

            return GcveCveData(
                cveId = record.cveMetadata.cveId,
                cnaSource = cna.providerMetadata?.shortName,
                publishedDate = publishedDate,
                lastUpdatedDate = lastUpdatedDate,
                description = description,
                cvssV31Score = bestCvssV31?.baseScore,
                cvssV31Severity = bestCvssV31?.baseSeverity,
                cvssV31Vector = bestCvssV31?.vectorString,
                cvssV40Score = bestCvssV40?.baseScore,
                cvssV40Severity = bestCvssV40?.baseSeverity,
                cvssV40Vector = bestCvssV40?.vectorString,
                cweIds = cweIds,
                references = references,
                hasExploitReference = hasExploitReference,
                hasPatchReference = hasPatchReference,
                ssvcExploitation = ssvcExploitation,
                ssvcAutomatable = ssvcAutomatable,
                ssvcTechnicalImpact = ssvcTechnicalImpact,
                hasKevEntry = kevMetric != null,
                kevDateAdded = kevMetric?.dateAdded,
                daysOld = publishedDate?.let { ChronoUnit.DAYS.between(it, now) } ?: 0,
                daysSinceModified = lastUpdatedDate?.let { ChronoUnit.DAYS.between(it, now) } ?: 0,
            )
        }

        private fun parseTimestamp(timestamp: String): LocalDateTime {
            return if (timestamp.endsWith('Z')) {
                ZonedDateTime.parse(timestamp).toLocalDateTime()
            } else {
                LocalDateTime.parse(timestamp, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            }
        }
    }
}

@Serializable
data class GcveCveMetadata(
    val cveId: String,
    val state: String,
    val assignerOrgId: String? = null,
    val assignerShortName: String? = null,
    val datePublished: String? = null,
    val dateUpdated: String? = null,
    val dateReserved: String? = null,
)

@Serializable
data class GcveContainers(
    val cna: GcveCnaContainer,
    val adp: List<GcveAdpContainer>? = null,
)

@Serializable
data class GcveCnaContainer(
    val title: String? = null,
    val providerMetadata: GcveProviderMetadata? = null,
    val descriptions: List<GcveDescription> = emptyList(),
    val affected: List<GcveAffected>? = null,
    val references: List<GcveReference> = emptyList(),
    val metrics: List<GcveMetricItem>? = null,
    val problemTypes: List<GcveProblemType>? = null,
)

@Serializable
data class GcveAdpContainer(
    val title: String? = null,
    val providerMetadata: GcveProviderMetadata? = null,
    val metrics: List<GcveMetricItem>? = null,
    val references: List<GcveReference>? = null,
)

@Serializable
data class GcveProviderMetadata(
    val orgId: String? = null,
    val shortName: String? = null,
    val dateUpdated: String? = null,
)

@Serializable
data class GcveDescription(
    val lang: String,
    val value: String,
)

@Serializable
data class GcveAffected(
    val vendor: String? = null,
    val product: String? = null,
    val versions: List<GcveVersion>? = null,
    val defaultStatus: String? = null,
)

@Serializable
data class GcveVersion(
    val version: String? = null,
    val status: String? = null,
    val lessThan: String? = null,
    val lessThanOrEqual: String? = null,
    val versionType: String? = null,
)

@Serializable
data class GcveReference(
    val url: String,
    val tags: List<String>? = null,
)

@Serializable
data class GcveMetricItem(
    val format: String? = null,
    val cvssV3_1: GcveCvssV31? = null,
    val cvssV4_0: GcveCvssV40? = null,
    val other: GcveOtherMetric? = null,
)

@Serializable
data class GcveCvssV31(
    val version: String? = null,
    val vectorString: String,
    val baseScore: Double,
    val baseSeverity: String,
    val attackVector: String? = null,
    val attackComplexity: String? = null,
    val privilegesRequired: String? = null,
    val userInteraction: String? = null,
    val scope: String? = null,
    val confidentialityImpact: String? = null,
    val integrityImpact: String? = null,
    val availabilityImpact: String? = null,
)

@Serializable
data class GcveCvssV40(
    val version: String? = null,
    val vectorString: String,
    val baseScore: Double,
    val baseSeverity: String,
    val attackVector: String? = null,
    val attackComplexity: String? = null,
)

@Serializable
data class GcveOtherMetric(
    val type: String,
    val content: GcveOtherMetricContent? = null,
)

@Serializable
data class GcveOtherMetricContent(
    val id: String? = null,
    val role: String? = null,
    val version: String? = null,
    val timestamp: String? = null,
    val options: List<Map<String, String>>? = null,
    val dateAdded: String? = null,
    val reference: String? = null,
    val other: String? = null,
)

@Serializable
data class GcveProblemType(
    val descriptions: List<GcveProblemTypeDescription> = emptyList(),
)

@Serializable
data class GcveProblemTypeDescription(
    val lang: String? = null,
    val description: String? = null,
    val type: String? = null,
    val cweId: String? = null,
)

// EPSS API response model

@Serializable
data class GcveEpssResponse(
    val status: String,
    @SerialName("status-code") val statusCode: Int,
    val version: String? = null,
    val access: String? = null,
    val total: Int,
    val offset: Int? = null,
    val limit: Int? = null,
    val data: List<GcveEpssData> = emptyList(),
)

@Serializable
data class GcveEpssData(
    val cve: String,
    val epss: String,
    val percentile: String,
    val date: String,
)

// Domain model (what we store in the database)

data class GcveCveData(
    val cveId: String,
    val cnaSource: String?,
    val publishedDate: LocalDateTime?,
    val lastUpdatedDate: LocalDateTime?,
    val description: String?,
    val cvssV31Score: Double?,
    val cvssV31Severity: String?,
    val cvssV31Vector: String?,
    val cvssV40Score: Double?,
    val cvssV40Severity: String?,
    val cvssV40Vector: String?,
    val cweIds: List<String>,
    val references: List<String>,
    val hasExploitReference: Boolean,
    val hasPatchReference: Boolean,
    val ssvcExploitation: String?,
    val ssvcAutomatable: String?,
    val ssvcTechnicalImpact: String?,
    val hasKevEntry: Boolean,
    val kevDateAdded: String?,
    val daysOld: Long,
    val daysSinceModified: Long,
)
