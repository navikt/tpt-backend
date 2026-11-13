package no.nav.tpt.domain.remediation

import kotlinx.serialization.Serializable

@Serializable
data class CopilotRemediationsResponse(
    val enabled: Boolean,
    val remediations: List<CopilotRemediationDto>,
)

@Serializable
data class CopilotRemediationDto(
    val repository: String,
    val vulnerabilityIdentifier: String,
    val packageName: String? = null,
    val status: CopilotRemediationStatus,
    val taskUrl: String? = null,
    val requestedAt: String,
)

@Serializable
enum class CopilotRemediationStatus { PENDING, STARTED }

@Serializable
data class CopilotRemediationStartRequest(
    val repository: String,
    val vulnerabilityIdentifier: String,
    val packageName: String? = null,
    val workloadId: String? = null,
    val returnPath: String,
    val force: Boolean = false,
)

@Serializable
data class CopilotRemediationStartResponse(
    val authorizeUrl: String? = null,
    val existingTaskUrl: String? = null,
)

@Serializable
data class CopilotRemediationCallbackRequest(
    val code: String,
    val state: String,
)

@Serializable
data class CopilotRemediationCallbackResponse(
    val taskUrl: String? = null,
    val returnPath: String,
    val alreadyStarted: Boolean,
)
