package no.nav.tpt.domain.remediation

import kotlinx.serialization.Serializable

sealed class RemediationException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class AiServiceException(message: String, cause: Throwable? = null) : RemediationException(message, cause)
    class DataFetchException(message: String, cause: Throwable? = null) : RemediationException(message, cause)
    class ValidationException(message: String) : RemediationException(message)
}

private val CVE_ID_REGEX = Regex("""^CVE-\d{4}-\d{4,}$""")
private val CONTROL_CHAR_REGEX = Regex("""[\p{Cntrl}]""")
private const val CVE_ID_MAX_LENGTH = 50

@Serializable
data class RemediationRequest(
    val cveId: String,
    val workloadName: String,
    val environment: String,
    val packageName: String,
    val packageEcosystem: String
) {
    fun validate() {
        if (cveId.length > CVE_ID_MAX_LENGTH || !CVE_ID_REGEX.matches(cveId))
            throw RemediationException.ValidationException("Invalid CVE ID format")
        listOf(
            "workloadName" to workloadName,
            "environment" to environment,
            "packageName" to packageName,
            "packageEcosystem" to packageEcosystem
        ).forEach { (field, value) ->
            if (CONTROL_CHAR_REGEX.containsMatchIn(value))
                throw RemediationException.ValidationException("Field '$field' contains invalid characters")
            val limit = if (field == "packageEcosystem" || field == "environment") 50 else 100
            if (value.length > limit)
                throw RemediationException.ValidationException("Field '$field' exceeds maximum length of $limit")
        }
    }
}
