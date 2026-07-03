package no.nav.tpt.infrastructure.admin

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.timestamp

object AdminReports : Table("admin_reports") {
    val reportType  = varchar("report_type", 50)
    val payload     = text("payload")
    val generatedAt = timestamp("generated_at")

    override val primaryKey = PrimaryKey(reportType)
}
