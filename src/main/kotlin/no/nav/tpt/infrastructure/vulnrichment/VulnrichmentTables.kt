package no.nav.tpt.infrastructure.vulnrichment

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.CurrentTimestamp
import org.jetbrains.exposed.v1.javatime.timestamp

object VulnrichmentTable : Table("vulnrichment_data") {
    val cveId = varchar("cve_id", 20)
    val exploitationStatus = varchar("exploitation_status", 20).nullable()
    val automatable = varchar("automatable", 10).nullable()
    val technicalImpact = varchar("technical_impact", 20).nullable()
    val lastUpdated = timestamp("last_updated").defaultExpression(CurrentTimestamp)
    val createdAt = timestamp("created_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(cveId)
}
