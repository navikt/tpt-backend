package no.nav.tpt.infrastructure.remediation

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.datetime

object RemediationCacheTable : Table("remediation_cache") {
    val cveId = varchar("cve_id", 50)
    val packageEcosystem = varchar("package_ecosystem", 100)
    val remediationText = text("remediation_text")
    val generatedAt = datetime("generated_at")

    override val primaryKey = PrimaryKey(cveId, packageEcosystem)
}
