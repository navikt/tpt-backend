package no.nav.tpt.domain.remediation

import kotlinx.serialization.Serializable

sealed class RemediationException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class AiServiceException(message: String, cause: Throwable? = null) : RemediationException(message, cause)
    class DataFetchException(message: String, cause: Throwable? = null) : RemediationException(message, cause)
}

@Serializable
data class RemediationRequest(
    val cveId: String,
    val workloadName: String,
    val environment: String,
    val packageName: String,
    val packageEcosystem: String
)
