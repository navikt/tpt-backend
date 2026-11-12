package no.nav.tpt.infrastructure.github.copilot

import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import java.time.Instant

class CopilotRemediationRepositoryImpl(private val database: Database) : CopilotRemediationRepository {

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction(database) { block() }

    override suspend fun findByRepository(repository: String): List<CopilotRemediation> = dbQuery {
        CopilotRemediationsTable.selectAll()
            .where { CopilotRemediationsTable.repository eq repository }
            .map { it.toRemediation() }
    }

    override suspend fun find(key: RemediationKey): CopilotRemediation? = dbQuery {
        CopilotRemediationsTable.selectAll()
            .where { matches(key) }
            .singleOrNull()
            ?.toRemediation()
    }

    override suspend fun tryClaim(
        key: RemediationKey,
        requestedBy: String,
        replaceableTaskId: String?,
        stalePendingBefore: Instant,
    ): Boolean = dbQuery {
        val now = Instant.now()
        val inserted = CopilotRemediationsTable.insertIgnore {
            it[repository] = key.repository
            it[vulnerabilityIdentifier] = key.vulnerabilityIdentifier
            it[packageName] = key.packageName
            it[status] = CopilotRemediationStatus.PENDING.name
            it[CopilotRemediationsTable.requestedBy] = requestedBy
            it[createdAt] = now
            it[updatedAt] = now
        }.insertedCount
        if (inserted == 1) return@dbQuery true

        val stalePending = (CopilotRemediationsTable.status eq CopilotRemediationStatus.PENDING.name) and
            (CopilotRemediationsTable.updatedAt less stalePendingBefore)
        val claimable = if (replaceableTaskId != null) {
            stalePending or ((CopilotRemediationsTable.status eq CopilotRemediationStatus.STARTED.name) and
                (CopilotRemediationsTable.taskId eq replaceableTaskId))
        } else {
            stalePending
        }

        CopilotRemediationsTable.update({ matches(key) and claimable }) {
            it[status] = CopilotRemediationStatus.PENDING.name
            it[CopilotRemediationsTable.requestedBy] = requestedBy
            it[updatedAt] = now
        } == 1
    }

    override suspend fun markStarted(key: RemediationKey, taskId: String, taskUrl: String?): Unit = dbQuery {
        CopilotRemediationsTable.update({ matches(key) }) {
            it[status] = CopilotRemediationStatus.STARTED.name
            it[CopilotRemediationsTable.taskId] = taskId
            it[CopilotRemediationsTable.taskUrl] = taskUrl
            it[createdAt] = Instant.now()
            it[updatedAt] = Instant.now()
        }
    }

    override suspend fun releaseClaim(key: RemediationKey): Unit = dbQuery {
        val pending = CopilotRemediationsTable.status eq CopilotRemediationStatus.PENDING.name
        CopilotRemediationsTable.deleteWhere { matches(key) and pending and taskId.isNull() }
        CopilotRemediationsTable.update({ matches(key) and pending }) {
            it[status] = CopilotRemediationStatus.STARTED.name
            it[updatedAt] = Instant.now()
        }
    }

    override suspend fun saveAuthorizationRequest(request: CopilotAuthorizationRequest): Unit = dbQuery {
        CopilotAuthorizationRequestsTable.deleteWhere { expiresAt less Instant.now() }
        CopilotAuthorizationRequestsTable.insert {
            it[state] = request.state
            it[codeVerifier] = request.codeVerifier
            it[requestedBy] = request.requestedBy
            it[repository] = request.key.repository
            it[vulnerabilityIdentifier] = request.key.vulnerabilityIdentifier
            it[packageName] = request.key.packageName
            it[workloadId] = request.workloadId
            it[returnPath] = request.returnPath
            it[expiresAt] = request.expiresAt
        }
    }

    override suspend fun consumeAuthorizationRequest(state: String): CopilotAuthorizationRequest? = dbQuery {
        val request = CopilotAuthorizationRequestsTable.selectAll()
            .where { CopilotAuthorizationRequestsTable.state eq state }
            .singleOrNull()
            ?.toAuthorizationRequest()
            ?: return@dbQuery null
        val deleted = CopilotAuthorizationRequestsTable.deleteWhere { CopilotAuthorizationRequestsTable.state eq state }
        if (deleted == 1) request else null
    }

    private fun matches(key: RemediationKey): Op<Boolean> =
        (CopilotRemediationsTable.repository eq key.repository) and
            (CopilotRemediationsTable.vulnerabilityIdentifier eq key.vulnerabilityIdentifier) and
            (CopilotRemediationsTable.packageName eq key.packageName)

    private fun ResultRow.toRemediation() = CopilotRemediation(
        key = RemediationKey(
            repository = this[CopilotRemediationsTable.repository],
            vulnerabilityIdentifier = this[CopilotRemediationsTable.vulnerabilityIdentifier],
            packageName = this[CopilotRemediationsTable.packageName],
        ),
        status = CopilotRemediationStatus.valueOf(this[CopilotRemediationsTable.status]),
        taskId = this[CopilotRemediationsTable.taskId],
        taskUrl = this[CopilotRemediationsTable.taskUrl],
        requestedBy = this[CopilotRemediationsTable.requestedBy],
        createdAt = this[CopilotRemediationsTable.createdAt],
        updatedAt = this[CopilotRemediationsTable.updatedAt],
    )

    private fun ResultRow.toAuthorizationRequest() = CopilotAuthorizationRequest(
        state = this[CopilotAuthorizationRequestsTable.state],
        codeVerifier = this[CopilotAuthorizationRequestsTable.codeVerifier],
        requestedBy = this[CopilotAuthorizationRequestsTable.requestedBy],
        key = RemediationKey(
            repository = this[CopilotAuthorizationRequestsTable.repository],
            vulnerabilityIdentifier = this[CopilotAuthorizationRequestsTable.vulnerabilityIdentifier],
            packageName = this[CopilotAuthorizationRequestsTable.packageName],
        ),
        workloadId = this[CopilotAuthorizationRequestsTable.workloadId],
        returnPath = this[CopilotAuthorizationRequestsTable.returnPath],
        expiresAt = this[CopilotAuthorizationRequestsTable.expiresAt],
    )
}
