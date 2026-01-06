package no.nav.tpt.infrastructure.nvd

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.CurrentTimestamp
import org.jetbrains.exposed.sql.javatime.date
import org.jetbrains.exposed.sql.javatime.timestamp

object NvdCves : Table("nvd_cves") {
    val cveId = varchar("cve_id", 20)
    val sourceIdentifier = varchar("source_identifier", 255).nullable()
    val vulnStatus = varchar("vuln_status", 50).nullable()

    val publishedDate = timestamp("published_date")
    val lastModifiedDate = timestamp("last_modified_date")

    // CISA KEV fields
    val cisaExploitAdd = date("cisa_exploit_add").nullable()
    val cisaActionDue = date("cisa_action_due").nullable()
    val cisaRequiredAction = text("cisa_required_action").nullable()
    val cisaVulnerabilityName = varchar("cisa_vulnerability_name", 500).nullable()

    // CVSS scores
    val cvssV31Score = decimal("cvss_v31_score", 3, 1).nullable()
    val cvssV31Severity = varchar("cvss_v31_severity", 20).nullable()
    val cvssV30Score = decimal("cvss_v30_score", 3, 1).nullable()
    val cvssV30Severity = varchar("cvss_v30_severity", 20).nullable()
    val cvssV2Score = decimal("cvss_v2_score", 3, 1).nullable()
    val cvssV2Severity = varchar("cvss_v2_severity", 20).nullable()

    // Content
    val description = text("description").nullable()
    val nvdReferences = text("nvd_references") // Stored as JSON text
    val cweIds = text("cwe_ids") // Stored as JSON text

    // Reference metadata
    val hasExploitReference = bool("has_exploit_reference").default(false)
    val hasPatchReference = bool("has_patch_reference").default(false)

    // Metadata
    val createdAt = timestamp("created_at").defaultExpression(CurrentTimestamp)
    val updatedAt = timestamp("updated_at").defaultExpression(CurrentTimestamp)

    override val primaryKey = PrimaryKey(cveId)
}
