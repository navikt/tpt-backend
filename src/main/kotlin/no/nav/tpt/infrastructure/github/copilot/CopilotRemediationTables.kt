package no.nav.tpt.infrastructure.github.copilot

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.dao.id.LongIdTable
import org.jetbrains.exposed.v1.javatime.CurrentTimestamp
import org.jetbrains.exposed.v1.javatime.timestamp

object CopilotRemediationsTable : LongIdTable("copilot_remediations") {
    val repository = varchar("repository", 255)
    val vulnerabilityIdentifier = varchar("vulnerability_identifier", 255)
    val packageName = varchar("package_name", 512)
    val status = varchar("status", 20)
    val taskId = varchar("task_id", 255).nullable()
    val taskUrl = text("task_url").nullable()
    val requestedBy = varchar("requested_by", 255)
    val createdAt = timestamp("created_at").defaultExpression(CurrentTimestamp)
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    init {
        uniqueIndex("uq_copilot_remediations_key", repository, vulnerabilityIdentifier, packageName)
    }
}

object CopilotAuthorizationRequestsTable : Table("copilot_authorization_requests") {
    val state = varchar("state", 128)
    val codeVerifier = varchar("code_verifier", 128)
    val requestedBy = varchar("requested_by", 255)
    val repository = varchar("repository", 255)
    val vulnerabilityIdentifier = varchar("vulnerability_identifier", 255)
    val packageName = varchar("package_name", 512)
    val workloadId = varchar("workload_id", 512).nullable()
    val returnPath = text("return_path")
    val expiresAt = timestamp("expires_at")

    override val primaryKey = PrimaryKey(state)
}
