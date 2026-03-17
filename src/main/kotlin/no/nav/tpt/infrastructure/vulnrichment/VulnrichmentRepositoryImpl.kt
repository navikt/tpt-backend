package no.nav.tpt.infrastructure.vulnrichment

import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

class VulnrichmentRepositoryImpl(private val database: Database) : VulnrichmentRepository {
    private val logger = LoggerFactory.getLogger(VulnrichmentRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction(database) { block() }

    override suspend fun getVulnrichmentData(cveId: String): VulnrichmentData? = dbQuery {
        VulnrichmentTable.selectAll().where { VulnrichmentTable.cveId eq cveId }
            .mapNotNull { toVulnrichmentData(it) }
            .singleOrNull()
    }

    override suspend fun getVulnrichmentDataBatch(cveIds: List<String>): Map<String, VulnrichmentData> = dbQuery {
        if (cveIds.isEmpty()) return@dbQuery emptyMap()
        VulnrichmentTable.selectAll().where { VulnrichmentTable.cveId inList cveIds }
            .mapNotNull { toVulnrichmentData(it) }
            .associateBy { it.cveId }
    }

    override suspend fun upsertVulnrichmentData(data: List<VulnrichmentData>) = dbQuery {
        if (data.isEmpty()) return@dbQuery

        data.chunked(500).forEach { chunk ->
            val existingIds = VulnrichmentTable
                .select(VulnrichmentTable.cveId)
                .where { VulnrichmentTable.cveId inList chunk.map { it.cveId } }
                .map { it[VulnrichmentTable.cveId] }
                .toSet()

            val toUpdate = chunk.filter { it.cveId in existingIds }
            val toInsert = chunk.filter { it.cveId !in existingIds }

            toUpdate.forEach { entry ->
                VulnrichmentTable.update({ VulnrichmentTable.cveId eq entry.cveId }) {
                    it[exploitationStatus] = entry.exploitationStatus
                    it[automatable] = entry.automatable
                    it[technicalImpact] = entry.technicalImpact
                    it[lastUpdated] = Instant.now()
                }
            }

            if (toInsert.isNotEmpty()) {
                VulnrichmentTable.batchInsert(toInsert) { entry ->
                    this[VulnrichmentTable.cveId] = entry.cveId
                    this[VulnrichmentTable.exploitationStatus] = entry.exploitationStatus
                    this[VulnrichmentTable.automatable] = entry.automatable
                    this[VulnrichmentTable.technicalImpact] = entry.technicalImpact
                }
            }
        }

        logger.info("Upserted ${data.size} Vulnrichment records")
    }

    override suspend fun getLastUpdated(): LocalDateTime? = dbQuery {
        VulnrichmentTable.select(VulnrichmentTable.lastUpdated)
            .orderBy(VulnrichmentTable.lastUpdated, SortOrder.DESC)
            .limit(1)
            .map { it[VulnrichmentTable.lastUpdated].atZone(java.time.ZoneId.of("UTC")).toLocalDateTime() }
            .singleOrNull()
    }

    private fun toVulnrichmentData(row: ResultRow): VulnrichmentData? {
        return try {
            VulnrichmentData(
                cveId = row[VulnrichmentTable.cveId],
                exploitationStatus = row[VulnrichmentTable.exploitationStatus],
                automatable = row[VulnrichmentTable.automatable],
                technicalImpact = row[VulnrichmentTable.technicalImpact],
            )
        } catch (e: Exception) {
            logger.warn("Failed to map Vulnrichment row: ${e.message}")
            null
        }
    }
}
