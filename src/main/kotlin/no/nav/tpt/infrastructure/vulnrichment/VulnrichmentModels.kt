package no.nav.tpt.infrastructure.vulnrichment

import kotlinx.serialization.Serializable

data class VulnrichmentData(
    val cveId: String,
    val exploitationStatus: String?,  // "active", "poc", "none"
    val automatable: String?,         // "yes", "no"
    val technicalImpact: String?,     // "total", "partial"
)

@Serializable
data class CveJson5(
    val cveMetadata: CveMetadata? = null,
    val containers: CveContainers? = null,
)

@Serializable
data class CveMetadata(
    val cveId: String,
)

@Serializable
data class CveContainers(
    val adp: List<AdpContainer>? = null,
)

@Serializable
data class AdpContainer(
    val providerMetadata: ProviderMetadata? = null,
    val metrics: List<AdpMetric>? = null,
)

@Serializable
data class ProviderMetadata(
    val shortName: String? = null,
)

@Serializable
data class AdpMetric(
    val other: OtherMetric? = null,
)

@Serializable
data class OtherMetric(
    val type: String? = null,
    val content: SsvcContent? = null,
)

@Serializable
data class SsvcContent(
    val id: String? = null,
    val options: List<Map<String, String>>? = null,
)
