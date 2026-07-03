package no.nav.tpt.infrastructure.admin

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class InMemoryAdminReportRepository : AdminReportRepository {
    private val store = ConcurrentHashMap<String, AdminReportRow>()

    override suspend fun saveReport(reportType: String, payload: String) {
        store[reportType] = AdminReportRow(payload = payload, generatedAt = Instant.now())
    }

    override suspend fun getReport(reportType: String): AdminReportRow? = store[reportType]
}
