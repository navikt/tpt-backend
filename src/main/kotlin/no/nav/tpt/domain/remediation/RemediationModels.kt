package no.nav.tpt.domain.remediation

import kotlinx.serialization.Serializable

@Serializable
data class RemediationRequest(
    val cveId: String,
    val workloadName: String,
    val environment: String,
    val packageName: String,
    val packageEcosystem: String
)
