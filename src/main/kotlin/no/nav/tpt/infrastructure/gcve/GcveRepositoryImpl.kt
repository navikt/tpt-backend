package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.json.Json
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import no.nav.tpt.infrastructure.vulnerability.Cves
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

class GcveRepositoryImpl(
    private val database: Database,
) : GcveRepository {
    private val logger = LoggerFactory.getLogger(GcveRepositoryImpl::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    private suspend fun <T> dbQuery(block: suspend () -> T): T = suspendTransaction(database) { block() }

    private fun LocalDateTime.toInstant(): Instant = this.toInstant(ZoneOffset.UTC)

    override suspend fun getCveData(cveId: String): GcveCveData? =
        dbQuery {
            GcveCves
                .selectAll()
                .where { GcveCves.cveId eq cveId }
                .mapNotNull { toGcveCveData(it) }
                .singleOrNull()
        }

    override suspend fun getCveDataBatch(cveIds: List<String>): Map<String, GcveCveData> =
        dbQuery {
            if (cveIds.isEmpty()) return@dbQuery emptyMap()
            GcveCves
                .selectAll()
                .where { GcveCves.cveId inList cveIds }
                .mapNotNull { toGcveCveData(it) }
                .associateBy { it.cveId }
        }

    override suspend fun upsertCve(cveData: GcveCveData, rawResponse: String?): GcveUpsertStats =
        dbQuery {
            upsertCves(listOf(cveData), if (rawResponse != null) mapOf(cveData.cveId to rawResponse) else emptyMap())
        }

    override suspend fun upsertCves(cves: List<GcveCveData>, rawResponses: Map<String, String>): GcveUpsertStats =
        dbQuery {
            if (cves.isEmpty()) return@dbQuery GcveUpsertStats(0, 0)

            var addedCount = 0
            var updatedCount = 0

            cves.chunked(100).forEach { chunk ->
                val cveIds = chunk.map { it.cveId }
                val existingCveIds = GcveCves
                    .select(GcveCves.cveId)
                    .where { GcveCves.cveId inList cveIds }
                    .map { it[GcveCves.cveId] }
                    .toSet()

                GcveCves.batchUpsert(
                    chunk,
                    GcveCves.cveId,
                    onUpdateExclude = listOf(GcveCves.createdAt),
                    shouldReturnGeneratedValues = false,
                ) { cveData ->
                    this[GcveCves.cveId] = cveData.cveId
                    this[GcveCves.cnaSource] = cveData.cnaSource
                    this[GcveCves.publishedDate] = cveData.publishedDate?.toInstant()
                    this[GcveCves.lastUpdatedDate] = cveData.lastUpdatedDate?.toInstant()
                    this[GcveCves.cvssV31Score] = cveData.cvssV31Score?.toBigDecimal()
                    this[GcveCves.cvssV31Severity] = cveData.cvssV31Severity
                    this[GcveCves.cvssV31Vector] = cveData.cvssV31Vector
                    this[GcveCves.cvssV40Score] = cveData.cvssV40Score?.toBigDecimal()
                    this[GcveCves.cvssV40Severity] = cveData.cvssV40Severity
                    this[GcveCves.cvssV40Vector] = cveData.cvssV40Vector
                    this[GcveCves.description] = cveData.description
                    this[GcveCves.cweIds] = json.encodeToString<List<String>>(cveData.cweIds)
                    this[GcveCves.gcveReferences] = json.encodeToString<List<String>>(cveData.references)
                    this[GcveCves.hasExploitReference] = cveData.hasExploitReference
                    this[GcveCves.hasPatchReference] = cveData.hasPatchReference
                    this[GcveCves.ssvcExploitation] = cveData.ssvcExploitation
                    this[GcveCves.ssvcAutomatable] = cveData.ssvcAutomatable
                    this[GcveCves.ssvcTechnicalImpact] = cveData.ssvcTechnicalImpact
                    this[GcveCves.hasKevEntry] = cveData.hasKevEntry
                    this[GcveCves.kevDateAdded] = cveData.kevDateAdded
                    this[GcveCves.rawResponse] = rawResponses[cveData.cveId]
                    this[GcveCves.fetchedAt] = Instant.now()
                    this[GcveCves.updatedAt] = Instant.now()
                }

                addedCount += chunk.count { it.cveId !in existingCveIds }
                updatedCount += chunk.count { it.cveId in existingCveIds }
            }

            logger.info("Upserted ${cves.size} GCVE CVEs (added: $addedCount, updated: $updatedCount)")
            GcveUpsertStats(addedCount, updatedCount)
        }

    override suspend fun getLastSyncTimestamp(): Instant? =
        dbQuery {
            GcveSyncStatusTable
                .selectAll()
                .where { GcveSyncStatusTable.id eq "default" }
                .firstOrNull()
                ?.get(GcveSyncStatusTable.lastSyncTimestamp)
        }

    override suspend fun updateSyncTimestamp(timestamp: Instant) {
        dbQuery {
            GcveSyncStatusTable.upsert(GcveSyncStatusTable.id) {
                it[id] = "default"
                it[lastSyncTimestamp] = timestamp
                it[updatedAt] = Instant.now()
            }
        }
    }

    override suspend fun getCveDataWithRaw(cveId: String): Pair<GcveCveData, String?>? =
        dbQuery {
            GcveCves
                .selectAll()
                .where { GcveCves.cveId eq cveId }
                .firstOrNull()
                ?.let { row -> Pair(toGcveCveData(row), row[GcveCves.rawResponse]) }
        }

    override suspend fun getTrackedCveIds(): Set<String> =
        dbQuery {
            Cves.select(Cves.id).map { it[Cves.id] }.toSet()
        }

    override suspend fun getAllStoredCveIds(): Set<String> =
        dbQuery {
            GcveCves.select(GcveCves.cveId).map { it[GcveCves.cveId] }.toSet()
        }

    private fun toGcveCveData(row: ResultRow): GcveCveData {
        val publishedInstant = row[GcveCves.publishedDate]
        val lastUpdatedInstant = row[GcveCves.lastUpdatedDate]
        val publishedDate = publishedInstant?.let { LocalDateTime.ofInstant(it, ZoneOffset.UTC) }
        val lastUpdatedDate = lastUpdatedInstant?.let { LocalDateTime.ofInstant(it, ZoneOffset.UTC) }
        val now = LocalDateTime.now()

        return GcveCveData(
            cveId = row[GcveCves.cveId],
            cnaSource = row[GcveCves.cnaSource],
            publishedDate = publishedDate,
            lastUpdatedDate = lastUpdatedDate,
            description = row[GcveCves.description],
            cvssV31Score = row[GcveCves.cvssV31Score]?.toDouble(),
            cvssV31Severity = row[GcveCves.cvssV31Severity],
            cvssV31Vector = row[GcveCves.cvssV31Vector],
            cvssV40Score = row[GcveCves.cvssV40Score]?.toDouble(),
            cvssV40Severity = row[GcveCves.cvssV40Severity],
            cvssV40Vector = row[GcveCves.cvssV40Vector],
            cweIds = row[GcveCves.cweIds]?.let { json.decodeFromString<List<String>>(it) } ?: emptyList(),
            references = row[GcveCves.gcveReferences]?.let { json.decodeFromString<List<String>>(it) } ?: emptyList(),
            hasExploitReference = row[GcveCves.hasExploitReference],
            hasPatchReference = row[GcveCves.hasPatchReference],
            ssvcExploitation = row[GcveCves.ssvcExploitation],
            ssvcAutomatable = row[GcveCves.ssvcAutomatable],
            ssvcTechnicalImpact = row[GcveCves.ssvcTechnicalImpact],
            hasKevEntry = row[GcveCves.hasKevEntry],
            kevDateAdded = row[GcveCves.kevDateAdded],
            daysOld = publishedDate?.let { ChronoUnit.DAYS.between(it, now) } ?: 0,
            daysSinceModified = lastUpdatedDate?.let { ChronoUnit.DAYS.between(it, now) } ?: 0,
        )
    }
}
