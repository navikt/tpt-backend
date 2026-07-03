package no.nav.tpt.infrastructure.admin

import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import java.time.Instant

class AdminReportRepositoryImpl(
    private val database: Database,
) : AdminReportRepository {

    private suspend fun <T> dbQuery(block: suspend () -> T): T = suspendTransaction(database) { block() }

    override suspend fun saveReport(reportType: String, payload: String) {
        dbQuery {
            AdminReports.upsert(AdminReports.reportType) {
                it[AdminReports.reportType]  = reportType
                it[AdminReports.payload]     = payload
                it[AdminReports.generatedAt] = Instant.now()
            }
        }
    }

    override suspend fun getReport(reportType: String): AdminReportRow? =
        dbQuery {
            AdminReports
                .selectAll()
                .where { AdminReports.reportType eq reportType }
                .singleOrNull()
                ?.let { row ->
                    AdminReportRow(
                        payload     = row[AdminReports.payload],
                        generatedAt = row[AdminReports.generatedAt],
                    )
                }
        }
}
