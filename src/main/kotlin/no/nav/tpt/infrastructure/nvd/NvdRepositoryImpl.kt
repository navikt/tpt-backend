package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

class NvdRepositoryImpl(private val database: Database) : NvdRepository {
    private val logger = LoggerFactory.getLogger(NvdRepositoryImpl::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        newSuspendedTransaction(Dispatchers.IO, database) { block() }

    private fun LocalDateTime.toInstant(): Instant = this.toInstant(ZoneOffset.UTC)

    override suspend fun getCveData(cveId: String): NvdCveData? = dbQuery {
        NvdCves.selectAll().where { NvdCves.cveId eq cveId }
            .mapNotNull { toNvdCveData(it) }
            .singleOrNull()
    }

    override suspend fun upsertCve(cve: NvdCveData): UpsertStats = dbQuery {
        upsertCves(listOf(cve))
    }

    override suspend fun upsertCves(cves: List<NvdCveData>): UpsertStats = dbQuery {
        if (cves.isEmpty()) return@dbQuery UpsertStats(0, 0)

        logger.info("Upserting ${cves.size} CVEs")

        var addedCount = 0
        var updatedCount = 0

        cves.chunked(500).forEach { chunk ->
            chunk.forEach { cveData ->
                val exists = NvdCves.selectAll().where { NvdCves.cveId eq cveData.cveId }.count() > 0

                if (exists) {
                    NvdCves.update({ NvdCves.cveId eq cveData.cveId }) {
                        it[sourceIdentifier] = cveData.sourceIdentifier
                        it[vulnStatus] = cveData.vulnStatus
                        it[publishedDate] = cveData.publishedDate.toInstant()
                        it[lastModifiedDate] = cveData.lastModifiedDate.toInstant()
                        it[cisaExploitAdd] = cveData.cisaExploitAdd
                        it[cisaActionDue] = cveData.cisaActionDue
                        it[cisaRequiredAction] = cveData.cisaRequiredAction
                        it[cisaVulnerabilityName] = cveData.cisaVulnerabilityName
                        it[cvssV31Score] = cveData.cvssV31Score?.toBigDecimal()
                        it[cvssV31Severity] = cveData.cvssV31Severity
                        it[cvssV30Score] = cveData.cvssV30Score?.toBigDecimal()
                        it[cvssV30Severity] = cveData.cvssV30Severity
                        it[cvssV2Score] = cveData.cvssV2Score?.toBigDecimal()
                        it[cvssV2Severity] = cveData.cvssV2Severity
                        it[description] = cveData.description
                        it[nvdReferences] = json.encodeToString<List<String>>(cveData.references)
                        it[cweIds] = json.encodeToString<List<String>>(cveData.cweIds)
                        it[hasExploitReference] = cveData.hasExploitReference
                        it[hasPatchReference] = cveData.hasPatchReference
                        it[updatedAt] = LocalDateTime.now().toInstant()
                    }
                    updatedCount++
                } else {
                    NvdCves.insert {
                        it[cveId] = cveData.cveId
                        it[sourceIdentifier] = cveData.sourceIdentifier
                        it[vulnStatus] = cveData.vulnStatus
                        it[publishedDate] = cveData.publishedDate.toInstant()
                        it[lastModifiedDate] = cveData.lastModifiedDate.toInstant()
                        it[cisaExploitAdd] = cveData.cisaExploitAdd
                        it[cisaActionDue] = cveData.cisaActionDue
                        it[cisaRequiredAction] = cveData.cisaRequiredAction
                        it[cisaVulnerabilityName] = cveData.cisaVulnerabilityName
                        it[cvssV31Score] = cveData.cvssV31Score?.toBigDecimal()
                        it[cvssV31Severity] = cveData.cvssV31Severity
                        it[cvssV30Score] = cveData.cvssV30Score?.toBigDecimal()
                        it[cvssV30Severity] = cveData.cvssV30Severity
                        it[cvssV2Score] = cveData.cvssV2Score?.toBigDecimal()
                        it[cvssV2Severity] = cveData.cvssV2Severity
                        it[description] = cveData.description
                        it[nvdReferences] = json.encodeToString<List<String>>(cveData.references)
                        it[cweIds] = json.encodeToString<List<String>>(cveData.cweIds)
                        it[hasExploitReference] = cveData.hasExploitReference
                        it[hasPatchReference] = cveData.hasPatchReference
                    }
                    addedCount++
                }
            }
        }

        logger.info("Successfully upserted ${cves.size} CVEs (added: $addedCount, updated: $updatedCount)")
        UpsertStats(addedCount, updatedCount)
    }

    override suspend fun getLastModifiedDate(): LocalDateTime? = dbQuery {
        val instant = NvdCves.selectAll()
            .orderBy(NvdCves.lastModifiedDate, SortOrder.DESC)
            .limit(1)
            .firstOrNull()
            ?.get(NvdCves.lastModifiedDate)

        instant?.let { LocalDateTime.ofInstant(it, ZoneOffset.UTC) }
    }

    override suspend fun getCvesInKev(): List<NvdCveData> = dbQuery {
        NvdCves.selectAll().where { NvdCves.cisaExploitAdd.isNotNull() }
            .mapNotNull { toNvdCveData(it) }
    }

    private fun toNvdCveData(row: ResultRow): NvdCveData {
        val publishedInstant = row[NvdCves.publishedDate]
        val lastModifiedInstant = row[NvdCves.lastModifiedDate]
        val publishedDate = LocalDateTime.ofInstant(publishedInstant, ZoneOffset.UTC)
        val lastModifiedDate = LocalDateTime.ofInstant(lastModifiedInstant, ZoneOffset.UTC)
        val now = LocalDateTime.now()

        return NvdCveData(
            cveId = row[NvdCves.cveId],
            sourceIdentifier = row[NvdCves.sourceIdentifier],
            vulnStatus = row[NvdCves.vulnStatus],
            publishedDate = publishedDate,
            lastModifiedDate = lastModifiedDate,
            cisaExploitAdd = row[NvdCves.cisaExploitAdd],
            cisaActionDue = row[NvdCves.cisaActionDue],
            cisaRequiredAction = row[NvdCves.cisaRequiredAction],
            cisaVulnerabilityName = row[NvdCves.cisaVulnerabilityName],
            cvssV31Score = row[NvdCves.cvssV31Score]?.toDouble(),
            cvssV31Severity = row[NvdCves.cvssV31Severity],
            cvssV30Score = row[NvdCves.cvssV30Score]?.toDouble(),
            cvssV30Severity = row[NvdCves.cvssV30Severity],
            cvssV2Score = row[NvdCves.cvssV2Score]?.toDouble(),
            cvssV2Severity = row[NvdCves.cvssV2Severity],
            description = row[NvdCves.description],
            references = json.decodeFromString<List<String>>(row[NvdCves.nvdReferences]),
            cweIds = json.decodeFromString<List<String>>(row[NvdCves.cweIds]),
            daysOld = java.time.temporal.ChronoUnit.DAYS.between(publishedDate, now),
            daysSinceModified = java.time.temporal.ChronoUnit.DAYS.between(lastModifiedDate, now),
            hasExploitReference = row[NvdCves.hasExploitReference],
            hasPatchReference = row[NvdCves.hasPatchReference]
        )
    }
}

