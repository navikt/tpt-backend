package no.nav.tpt.infrastructure.gcve

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.CurrentTimestamp
import org.jetbrains.exposed.v1.javatime.date
import org.jetbrains.exposed.v1.javatime.timestamp

object GcveSightingsSummaryTable : Table("gcve_sightings_summary") {
    val cveId = varchar("cve_id", 50)
    val exploitedCount = integer("exploited_count").default(0)
    val pocCount = integer("poc_count").default(0)
    val seenCount = integer("seen_count").default(0)
    val latestExploitedAt = timestamp("latest_exploited_at").nullable()
    val latestPocAt = timestamp("latest_poc_at").nullable()
    val latestSeenAt = timestamp("latest_seen_at").nullable()
    val createdAt = timestamp("created_at").defaultExpression(CurrentTimestamp)
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(cveId)
}

object GcveSightingsSyncStateTable : Table("gcve_sightings_sync_state") {
    val id = integer("id").default(1)
    val lastFetchedDate = date("last_fetched_date")
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(id)
}
