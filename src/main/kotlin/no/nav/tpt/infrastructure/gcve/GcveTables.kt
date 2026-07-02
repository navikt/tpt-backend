package no.nav.tpt.infrastructure.gcve

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.CurrentTimestamp
import org.jetbrains.exposed.v1.javatime.timestamp

object GcveCves : Table("gcve_cves") {
    val cveId = varchar("cve_id", 50)
    val cnaSource = varchar("cna_source", 100).nullable()

    val publishedDate = timestamp("published_date").nullable()
    val lastUpdatedDate = timestamp("last_updated_date").nullable()

    val cvssV31Score = decimal("cvss_v31_score", 3, 1).nullable()
    val cvssV31Severity = varchar("cvss_v31_severity", 20).nullable()
    val cvssV31Vector = varchar("cvss_v31_vector", 200).nullable()

    val cvssV40Score = decimal("cvss_v40_score", 3, 1).nullable()
    val cvssV40Severity = varchar("cvss_v40_severity", 20).nullable()
    val cvssV40Vector = varchar("cvss_v40_vector", 200).nullable()

    val description = text("description").nullable()
    val cweIds = text("cwe_ids").nullable()
    val gcveReferences = text("gcve_references").nullable()

    val hasExploitReference = bool("has_exploit_reference").default(false)
    val hasPatchReference = bool("has_patch_reference").default(false)

    val ssvcExploitation = varchar("ssvc_exploitation", 20).nullable()
    val ssvcAutomatable = varchar("ssvc_automatable", 10).nullable()
    val ssvcTechnicalImpact = varchar("ssvc_technical_impact", 20).nullable()

    val hasKevEntry = bool("has_kev_entry").default(false)
    val kevDateAdded = varchar("kev_date_added", 20).nullable()

    val rawResponse = text("raw_response").nullable()

    val fetchedAt = timestamp("fetched_at").defaultExpression(CurrentTimestamp)
    val createdAt = timestamp("created_at").defaultExpression(CurrentTimestamp)
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(cveId)
}

object GcveSyncStatusTable : Table("gcve_sync_status") {
    val id = varchar("id", 50)
    val lastSyncTimestamp = timestamp("last_sync_timestamp")
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(id)
}
