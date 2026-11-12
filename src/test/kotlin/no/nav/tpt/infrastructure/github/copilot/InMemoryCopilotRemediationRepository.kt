package no.nav.tpt.infrastructure.github.copilot

import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import java.time.Instant

class InMemoryCopilotRemediationRepository : CopilotRemediationRepository {
    val remediations = mutableMapOf<RemediationKey, CopilotRemediation>()
    val authorizationRequests = mutableMapOf<String, CopilotAuthorizationRequest>()

    override suspend fun findByRepository(repository: String) =
        remediations.values.filter { it.key.repository == repository }

    override suspend fun find(key: RemediationKey) = remediations[key]

    override suspend fun tryClaim(
        key: RemediationKey,
        requestedBy: String,
        replaceableTaskId: String?,
        stalePendingBefore: Instant,
    ): Boolean {
        val existing = remediations[key]
        val now = Instant.now()
        val claimable = existing == null ||
            (existing.status == CopilotRemediationStatus.PENDING && existing.updatedAt.isBefore(stalePendingBefore)) ||
            (replaceableTaskId != null && existing.status == CopilotRemediationStatus.STARTED &&
                existing.taskId == replaceableTaskId)
        if (!claimable) return false
        remediations[key] = existing?.copy(status = CopilotRemediationStatus.PENDING, requestedBy = requestedBy, updatedAt = now)
            ?: CopilotRemediation(key, CopilotRemediationStatus.PENDING, null, null, requestedBy, now, now)
        return true
    }

    override suspend fun markStarted(key: RemediationKey, taskId: String, taskUrl: String?) {
        val existing = remediations.getValue(key)
        remediations[key] = existing.copy(status = CopilotRemediationStatus.STARTED, taskId = taskId, taskUrl = taskUrl)
    }

    override suspend fun releaseClaim(key: RemediationKey) {
        val existing = remediations[key] ?: return
        if (existing.status != CopilotRemediationStatus.PENDING) return
        if (existing.taskId == null) {
            remediations.remove(key)
        } else {
            remediations[key] = existing.copy(status = CopilotRemediationStatus.STARTED)
        }
    }

    override suspend fun saveAuthorizationRequest(request: CopilotAuthorizationRequest) {
        authorizationRequests[request.state] = request
    }

    override suspend fun consumeAuthorizationRequest(state: String) = authorizationRequests.remove(state)
}
