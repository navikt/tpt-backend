package no.nav.tpt.infrastructure.sse

import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.greater
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insertAndGetId
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import java.time.Instant
import java.time.temporal.ChronoUnit

class SseEventLogRepository(
    private val database: Database,
) : SseEventPublisher {
    private val json = Json { ignoreUnknownKeys = true }

    companion object {
        const val BATCH_SIZE = 500
    }

    override suspend fun publish(event: SseEvent): SseEventEnvelope =
        suspendTransaction(database) {
            exec("SELECT pg_advisory_xact_lock(874503212)")
            val payload = json.encodeToString(SseEvent.serializer(), event)
            val id = SseEventLogTable.insertAndGetId {
                it[type] = eventType(event)
                it[SseEventLogTable.payload] = payload
            }.value
            exec("SELECT pg_notify('sse_event_log', '$id')")
            SseEventEnvelope(id, event)
        }

    suspend fun eventsAfter(id: Long, limit: Int = BATCH_SIZE): List<SseEventEnvelope> =
        suspendTransaction(database) {
            SseEventLogTable
                .selectAll()
                .where { SseEventLogTable.id greater id }
                .orderBy(SseEventLogTable.id to SortOrder.ASC)
                .limit(limit)
                .map { row ->
                    SseEventEnvelope(
                        id = row[SseEventLogTable.id].value,
                        event = json.decodeFromString(SseEvent.serializer(), row[SseEventLogTable.payload]),
                    )
                }
        }

    suspend fun latestEventId(): Long =
        suspendTransaction(database) {
            SseEventLogTable
                .selectAll()
                .orderBy(SseEventLogTable.id to SortOrder.DESC)
                .limit(1)
                .singleOrNull()
                ?.get(SseEventLogTable.id)
                ?.value ?: 0L
        }

    suspend fun deleteOlderThanOneHour(): Int =
        suspendTransaction(database) {
            val cutoff = Instant.now().minus(1, ChronoUnit.HOURS)
            SseEventLogTable.deleteWhere { SseEventLogTable.createdAt less cutoff }
        }

    private fun eventType(event: SseEvent): String =
        when (event) {
            is SseEvent.TeamSyncStarted -> "team_sync_started"
            is SseEvent.TeamSyncComplete -> "team_sync_complete"
            is SseEvent.GcveSyncComplete -> "gcve_sync_complete"
            is SseEvent.GitHubVulnSyncStarted -> "github_vuln_sync_started"
            is SseEvent.GitHubVulnSyncComplete -> "github_vuln_sync_complete"
        }
}
