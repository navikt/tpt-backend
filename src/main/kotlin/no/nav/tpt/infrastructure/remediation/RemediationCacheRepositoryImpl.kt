package no.nav.tpt.infrastructure.remediation

import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import java.time.LocalDateTime

class RemediationCacheRepositoryImpl(private val database: Database) : RemediationCacheRepository {

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction(database) { block() }

    override suspend fun getCached(cveId: String, packageEcosystem: String): CachedRemediation? =
        dbQuery {
            RemediationCacheTable
                .selectAll()
                .where {
                    (RemediationCacheTable.cveId eq cveId) and
                    (RemediationCacheTable.packageEcosystem eq packageEcosystem)
                }
                .singleOrNull()
                ?.let {
                    CachedRemediation(
                        remediationText = it[RemediationCacheTable.remediationText],
                        generatedAt = it[RemediationCacheTable.generatedAt]
                    )
                }
        }

    override suspend fun saveCache(cveId: String, packageEcosystem: String, remediationText: String) {
        dbQuery {
            RemediationCacheTable.upsert {
                it[RemediationCacheTable.cveId] = cveId
                it[RemediationCacheTable.packageEcosystem] = packageEcosystem
                it[RemediationCacheTable.remediationText] = remediationText
                it[RemediationCacheTable.generatedAt] = LocalDateTime.now()
            }
        }
    }
}
