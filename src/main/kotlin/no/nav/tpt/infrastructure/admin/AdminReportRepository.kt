package no.nav.tpt.infrastructure.admin

import java.time.Instant

interface AdminReportRepository {
    suspend fun saveReport(reportType: String, payload: String)
    suspend fun getReport(reportType: String): AdminReportRow?
}

data class AdminReportRow(
    val payload: String,
    val generatedAt: Instant,
)
