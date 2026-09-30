package no.nav.tpt.infrastructure.sse

import org.jetbrains.exposed.v1.core.dao.id.LongIdTable
import org.jetbrains.exposed.v1.javatime.timestamp

object SseEventLogTable : LongIdTable("sse_event_log") {
    val type = varchar("type", 100)
    val payload = text("payload")
    val createdAt = timestamp("created_at")
}
