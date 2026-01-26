package no.nav.tpt.infrastructure.cisa

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant

object KevCatalogMetadata : Table("kev_catalog_metadata") {
    val id = integer("id").autoIncrement()
    val catalogTitle = varchar("catalog_title", 255)
    val catalogVersion = varchar("catalog_version", 50)
    val dateReleased = varchar("date_released", 30)
    val vulnerabilityCount = integer("vulnerability_count")
    val lastUpdated = timestamp("last_updated").default(Instant.now())
    val createdAt = timestamp("created_at").default(Instant.now())

    override val primaryKey = PrimaryKey(id)
}

object KevVulnerabilities : Table("kev_vulnerabilities") {
    val cveId = varchar("cve_id", 20)
    val catalogId = integer("catalog_id").references(KevCatalogMetadata.id)
    val vendorProject = varchar("vendor_project", 500)
    val product = varchar("product", 500)
    val vulnerabilityName = varchar("vulnerability_name", 1000)
    val dateAdded = varchar("date_added", 30)
    val shortDescription = text("short_description")
    val requiredAction = text("required_action")
    val dueDate = varchar("due_date", 30)
    val knownRansomwareCampaignUse = varchar("known_ransomware_campaign_use", 20)
    val notes = text("notes")
    val cwes = text("cwes")
    val createdAt = timestamp("created_at").default(Instant.now())

    override val primaryKey = PrimaryKey(cveId)
}
