package no.nav.tpt.infrastructure.github.copilot

import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import java.time.Instant

data class RemediationKey(
    val repository: String,
    val vulnerabilityIdentifier: String,
    val packageName: String,
)

/** The vulnerability as identified by its source (GitHub or Nais), used to look it up again in the callback. */
data class VulnerabilityRef(
    val repository: String,
    val vulnerabilityIdentifier: String,
    val packageName: String?,
)

data class CopilotRemediation(
    val key: RemediationKey,
    val status: CopilotRemediationStatus,
    val taskId: String?,
    val taskUrl: String?,
    val requestedBy: String,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class CopilotAuthorizationRequest(
    val state: String,
    val codeVerifier: String,
    val requestedBy: String,
    val vulnerability: VulnerabilityRef,
    val workloadId: String?,
    val returnPath: String,
    val expiresAt: Instant,
)

interface CopilotRemediationRepository {
    suspend fun findByRepository(repository: String): List<CopilotRemediation>
    suspend fun find(key: RemediationKey): CopilotRemediation?

    /**
     * Claims the key for starting a new task. Succeeds when no row exists, when the row's current task is
     * [replaceableTaskId], or when a previous claim has been pending longer than [stalePendingBefore].
     */
    suspend fun tryClaim(
        key: RemediationKey,
        requestedBy: String,
        replaceableTaskId: String?,
        stalePendingBefore: Instant,
    ): Boolean

    suspend fun markStarted(key: RemediationKey, taskId: String, taskUrl: String?)
    suspend fun releaseClaim(key: RemediationKey)

    suspend fun saveAuthorizationRequest(request: CopilotAuthorizationRequest)
    suspend fun consumeAuthorizationRequest(state: String): CopilotAuthorizationRequest?
}
